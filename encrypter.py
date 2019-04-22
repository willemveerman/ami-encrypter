import boto3 as b
from botocore.exceptions import ClientError
import datetime as dt
import json
import time
import random
from multiprocessing.dummy import Pool as ThreadPool
import logging
import argparse

parser = argparse.ArgumentParser(description=
                                 """
                                 Produces encrypted copies of AMIs, utilises parallelism in order to increase speed.
                            
                                 Requires a JSON input file.
                                 
                                 The JSON defines a search filter used to retrieve source AMIs.
                                 
                                 The JSON must be a dict with single key of type string, with value list of strings.
                                 
                                 The dict key and each list string are used as Name:Values input to Filters parameter
                                 of the AWS describe_images API.
                                 
                                 For example, this dict: { 'name' : ['alpha', 'beta']} would query the API twice: 
                                 once for an AMI with a 'name' value of 'alpha' and once with name 'beta'.
                                 
                                 The syntax accepted by the Filters parameter can be viewed here: 
                                 
                                 https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-images.html
                                 
                                 For each describe_images API call, if more than one AMI is returned 
                                 the script will select the most recent.
                                 
                                 If the filters in the JSON file return no AMIs the script will declare this but
                                 it will not raise an error. You can force the script to raise an error if any filters
                                 return no AMIs by using the -s --strict flag.
                                 
                                 In order to increase speed, the script can perform multiple encryptions in parallel.
                                 
                                 The degree of parallelism can be determined by the -c --concurrency flag.
                                 
                                 There is a limit to the number of concurrent CopySnaphot operations 
                                 that the AWS API will permit.
                                 
                                 If the script is denied initiating a CopySnapshot operation, it will briefly sleep
                                 and then try again; you can increase the encryption rate by asking AWS to raise
                                 the concurrent CopySnapshot limit for your account.
                                 """,
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('source',
                    help='path to JSON input')

parser.add_argument('-p', '--profile',
                    help='AWS credentials profile',
                    required=False)

parser.add_argument('-r', '--region',
                    help='AWS region',
                    required=False)

parser.add_argument('-s', '--strict',
                    action="store_true",
                    help='raise error if any input filter returns no results')

parser.add_argument('-c', '--concurrency',
                    help='number of concurrent encryption operations',
                    default=5,
                    required=False)

parser.add_argument('-v', '--verbose',
                    action="store_true",
                    help='display verbose output for debugging')

parser.add_argument('-i', '--info',
                    help='return qualifying AMIs but do not encrypt',
                    action="store_true")


class Encrypter:

    def __init__(self, profile="", region=""):
        self.profile = profile
        self.region = region
        self.timestamp = str(dt.datetime.now().timestamp()).split('.')[0]
        self.unprocessed = []
        self.processed = []

    def parse_json_file(self, filepath):
        """
        Parses JSON input file, confirms it meets criteria:
        - dict with single key of type string with value of type list (e.g. {"key": ['one','two']})
        - list composed only of strings

        returns list of Name:Value tuples [(dict_key, list[n]), (dict_key, list[n+1])]

        :param filepath: str
        :return: list of (str, str)
        """

        with open(filepath, 'r') as amis:
            try:
                ami_json = json.load(amis)
            except json.decoder.JSONDecodeError as json_error:
                raise ValueError("JSON improperly formatted: %s" % str(json_error))

        if isinstance(ami_json, dict):
            if len(ami_json) == 1:
                key_name = next(iter(ami_json))
                if isinstance(ami_json[key_name], list):
                    if all(isinstance(item, str) for item in ami_json[key_name]):
                        unique_ami_filters = [(key_name, ami_name) for ami_name in ami_json[key_name]]
                        logging.info("Found unique filters: ")
                        [logging.info(ami_filter[0]+":"+ami_filter[1]) for ami_filter in unique_ami_filters]
                        return unique_ami_filters
                    raise ValueError("'%s' list contains non-string values" % next(iter(ami_json)))
                raise ValueError("'{0}' value wrong datatype: {1} - should be array".format(key_name, str(type(ami_json[key_name]))))
            raise ValueError("JSON must be dict with single key, found %s keys" % len(ami_json))
        raise ValueError("JSON root wrong datatype: %s - should be dict" % str(type(ami_json)))

    def make_session(self):
        """
        Creates a boto3 Session, either with user-supplied credentials or those of the environment

        :return: boto3.resource.ec2, boto3.client.ec2
        """

        if self.profile and self.region:
            sess = b.Session(profile_name=self.profile, region_name=self.region)
        else:
            sess = b.Session()
            self.region = sess.region_name

        return sess.resource('ec2'), sess.client('ec2')

    def get_latest_image(self, ami_filter, client):
        """
        Uses ami_filter[0], ami_filter[1] as Name:Values input to Filters parameter of AWS describe_images API
        Returns most recent image if more than one returned from API

        :param ami_filter: (str, str)
        :param client: boto3.ec2.client
        :return: boto3.client.image
        """

        operation = "GET_LATEST_IMAGE"
        filter_message = "'{0}' filter with value '{1}'".format(ami_filter[0], ami_filter[1])

        try:
            image_list = client.describe_images(Filters=[
                {
                    'Name': '{0}'.format(ami_filter[0]),
                    'Values': [
                        '{0}'.format(ami_filter[1]),
                    ]
                },
            ]
            )
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidParameterValue':
                message = operation+": failed {0} due to API error: {1}".format(filter_message,
                                                                                e.response['Error']['Message'])
                if args.strict:
                    raise Exception(message)

                self.unprocessed.append(ami_filter)
                logging.info(message)

                return

            else:
                raise e

        if len(image_list['Images']) == 0:

            message = operation+": zero images returned by {0}".format(filter_message)

            if args.strict:
                raise Exception(message)

            self.unprocessed.append(ami_filter)
            logging.info(message)

            return

        if len(image_list['Images']) == 1:
            logging.info(operation+": one image returned by {0}: {1} - {2} "
                         .format(filter_message,
                                 image_list['Images'][0]['Name'],
                                 image_list['Images'][0]['ImageId']))
            return image_list['Images'][0]

        latest_image = ("", dt.datetime(2006, 3, 18, 0, 0, 0), "")  # pre AWS epoch

        for image in image_list['Images']:
            parsed_date = dt.datetime.strptime(image['CreationDate'], '%Y-%m-%dT%H:%M:%S.000Z')
            if parsed_date > latest_image[1]:
                latest_image = (image, parsed_date, image['CreationDate'])

        logging.info(operation+": {0} images returned by {1}, latest is {2} - {3} - {4}"
                     .format(str(len(image_list['Images'])),
                             filter_message,
                             latest_image[0]['Name'],
                             latest_image[0]['ImageId'],
                             latest_image[2]))

        return latest_image[0]

    def copy_single_snapshot(self, block, image, client):
        """
        Produces an encrypted copy of the snapshot ID referenced within block
        If successful, adds new key 'EncryptedCopy' to block['Ebs'] dict with value encrypted snapshot ID

        :param block: boto3.ec2.image.BlockDeviceMapping
        :param image: boto3.ec2.image
        :param client: boto3.ec2.client
        :return:
        """

        operation = "COPY_SNAPSHOT"

        logging.info(operation+": attempting to produce encrypted copy of {0} - {1}"
                     .format(block['Ebs']['SnapshotId'], image['Name']))

        try:
            encrypted_copy = client.copy_snapshot(SourceSnapshotId=block['Ebs']['SnapshotId'],
                                                  Encrypted=True,
                                                  SourceRegion=self.region)

            block['Ebs']['EncryptedCopy'] = encrypted_copy
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceLimitExceeded':
                sleep = random.randint(14, 31)
                logging.info(operation+": API limit exceeded: sleeping {0}s then retrying {1} - {2}"
                             .format(sleep, block['Ebs']['SnapshotId'], image['Name']))
                time.sleep(sleep)
                self.copy_single_snapshot(block, image, client)
            else:
                raise Exception(operation+": aborting copy of {0} from {1} due to API error: {2}"
                                .format(block['Ebs']['SnapshotId'], image['Name'], e.response['Error']['Message']))


    def build_encrypted_image_object(self, image, client, ec2):
        """
        Loops over an AMI's EBS volume mappings and attempts to produce
        an encrypted copy of each volume's underlying snapshot.

        If all snapshots are successfully copied, each volume's snapshot ID is replaced with that of its encrypted copy.

        :param image: boto3.ec2.image
        :param client: boto3.ec2.client
        :param ec2: boto3.ec2.resource
        :return:
        """

        for block in image['BlockDeviceMappings']:
            self.copy_single_snapshot(block, image, client)

        for block in image['BlockDeviceMappings']:
            block['Ebs']['SnapshotId'] = block['Ebs']['EncryptedCopy']['SnapshotId']
            block['Ebs'].pop('EncryptedCopy', None)
            block['Ebs'].pop('Encrypted', None)
            snapshot = ec2.Snapshot(block['Ebs']['SnapshotId'])
            snapshot.load()
            snapshot.wait_until_completed()

        return image

    def register_image(self, image, client):
        """
        Registers a new image from an input image object, using the input's EBS mappings for those of the new image.

        :param image: boto3.ec2.image
        :param client: boto3.ec2.client
        :return:
        """

        operation = "REGISTER_IMAGE"

        new_image_name = image['Name'].split('_')[0] + '_' + self.timestamp

        logging.info(operation+": attempting to register new AMI with name {0}, produced from AMI {1}"
                     .format(image['Name'], new_image_name))

        try:
            client.register_image(Name=new_image_name,
                                  Architecture='x86_64',
                                  RootDeviceName=image['RootDeviceName'],
                                  BlockDeviceMappings=image['BlockDeviceMappings'],
                                  VirtualizationType='hvm')

            self.processed.append(new_image_name)
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidAMIName.Duplicate':
                logging.info(operation+": AMI with name '{0}' already registered - skipping"
                             .format(new_image_name))
            else:
                raise Exception(operation+": aborting registration of {0} from {1} due to API error: {2}"
                                .format(new_image_name, image['Name'], e.response['Error']['Message']))

    def encrypt_ami(self, ami_filter):
        """
        Finds the latest AMI that corresponds to ami_filter
        Copies and encrypts AMI's snapshots and then registers a new AMI using the encrypted snapshots
        The original AMI's block device mappings are used to create those of the new,
        so the new AMI is an encrypted replica of the original

        :param ami_filter:
        :return:
        """

        ec2, client = self.make_session()

        latest_image = self.get_latest_image(ami_filter, client)

        encrypted_image_object = self.build_encrypted_image_object(latest_image, client, ec2)

        self.register_image(encrypted_image_object, client)


    def parallel_process(self, concurrency, filepath):
        """
        Takes a path to a JSON file as input, calls encrypt_ami concurrently

        :param concurrency: int
        :param filepath: str
        :return:
        """

        self.unprocessed = []
        self.processed = []

        self.timestamp = str(dt.datetime.now().timestamp()).split('.')[0]

        ami_filter_list = self.parse_json_file(filepath)

        pool = ThreadPool(concurrency)

        pool.map(self.encrypt_ami, ami_filter_list)

        self.log_results()

    def log_results(self):
        """
        Logs results to console.

        :return:
        """

        logging.info("Processing complete.\n")

        if self.processed:
            logging.info("{0} encrypted AMIs created:\n".format(len(self.processed)))
            [logging.info(new_ami) for new_ami in self.processed]
        if self.unprocessed:
            logging.info("\n{0} filters returned no results:\n".format(str(len(self.unprocessed))))
            [logging.info("{0} - {1}".format(ami_filter[0], ami_filter[1])) for ami_filter in self.unprocessed]


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')

    encrypter = Encrypter()

    args = parser.parse_args()

    if (args.profile and not args.region) or (args.region and not args.profile):
        parser.error('specifying --profile necessitates specifying --region, and vice versa')

    if args.profile:
        encrypter.profile = args.profile
        encrypter.region = args.region

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(message)s')

    if args.info:
        filter_list = encrypter.parse_json_file(args.source)
        ec2, client = encrypter.make_session()
        for f in filter_list:
            encrypter.get_latest_image(f, client)
        encrypter.log_results()
        exit(0)

    encrypter.parallel_process(args.concurrency, args.source)