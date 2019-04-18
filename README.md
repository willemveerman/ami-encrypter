AMI Encrypter
=============

ami-encrypter is a python module and command-line program for producing encrypted copies of amazon machine images (AMIs).


### Dependencies

* boto3
* python 3

[Boto3](https://boto3.amazonaws.com) can be installed as follows:

```shell
pip3 install --user boto3
```


### Usage

ami-encrypter can be used as a command-line program. 

It has one mandatory argument: the path to an input file. This parameter is the only positional argument that it accepts.

The most minimal usage example is as follows:

```shell
python3 encrypter.py /path/to/input.json
```

An example json input file is included in this repository.

Other parameters are optional and called using flags.

Credentials can be passed to the script usage the `--profile` and `--region` flags. Note that if passing parameters using these flags, both must be populated.

If credentials are not passed explicitly, the script will follow [boto3's behaviour for authentication.](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/configuration.html)

Calling the program with the `-h` flag will display help, as below.

```
usage: encrypter.py [-h] [-p PROFILE] [-r REGION] [-s] [-c CONCURRENCY] [-v]
                    [-i]
                    source

Produces encrypted copies of AMIs, utilises parallelism in order to increase
speed. Requires a JSON input file. The JSON defines a search filter used to
retrieve source AMIs. The JSON must be a dict with single key of type string,
with value list of strings. The dict key and each list string are used as
Name:Values input to Filters parameter of the AWS describe_images API. For
example, this dict: { 'name' : ['alpha', 'beta']} would query the API twice:
once for an AMI with a 'name' value of 'alpha' and once with name 'beta'. The
syntax accepted by the Filters parameter can be viewed here:
https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-images.html For
each describe_images API call, if more than one AMI is returned the script
will select the most recent. If the filters in the JSON file return no AMIs
the script will declare this but it will not raise an error. You can force the
script to raise an error if any filters return no AMIs by using the -s
--strict flag. In order to increase speed, the script can perform multiple
encryptions in parallel. The degree of parallelism can be determined by the -c
--concurrency flag. There is a limit to the number of concurrent CopySnaphot
operations that the AWS API will permit. If the script is denied initiating a
CopySnapshot operation, it will briefly sleep and then try again; you can
increase the encryption rate by asking AWS to raise the concurrent
CopySnapshot limit for your account.

positional arguments:
  source                path to JSON input

optional arguments:
  -h, --help            show this help message and exit
  -p PROFILE, --profile PROFILE
                        AWS credentials profile (default: None)
  -r REGION, --region REGION
                        AWS region (default: None)
  -s, --strict          raise error if any input filter returns no results
                        (default: False)
  -c CONCURRENCY, --concurrency CONCURRENCY
                        number of concurrent encryption operations (default:
                        5)
  -v, --verbose         display verbose output for debugging (default: False)
  -i, --info            return qualifying AMIs but do not encrypt (default:
                        False)
```

