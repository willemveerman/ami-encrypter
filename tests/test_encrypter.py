import unittest
from encrypter import Encrypter
import os.path
import tempfile
import json
from unittest.mock import patch, Mock
from botocore.exceptions import ClientError

class EncrypterFileParser(unittest.TestCase):

    tmpfilepath = os.path.join(tempfile.gettempdir(), "tmp-testfile")

    def setUp(self):
        self.test_dict = {"key": ['a', 'b', 'c']}
        with open(self.tmpfilepath, "w") as f:
            json.dump(self.test_dict, f)

        self.encrypter = Encrypter()

    def test_good_json(self):
        self.assertTrue(("key", 'a') in self.encrypter.parse_json_file(self.tmpfilepath))

    def test_bad_json(self):
        with open(self.tmpfilepath, "a") as f:
            f.write('aaaa,,,')
        with self.assertRaises(Exception) as e:
            self.encrypter.parse_json_file(self.tmpfilepath)
        self.assertTrue("JSON improperly formatted" in str(e.exception))

    def test_root_not_dict(self):
        with open(self.tmpfilepath, "w") as f:
            json.dump([1,2], f)
        with self.assertRaises(Exception) as e:
            self.encrypter.parse_json_file(self.tmpfilepath)
        self.assertTrue("JSON root wrong datatype" in str(e.exception))

    def test_two_keys(self):
        with open(self.tmpfilepath, "w") as f:
            json.dump({"key1": ['a', 'b'], "key2": []}, f)
        with self.assertRaises(Exception) as e:
            self.encrypter.parse_json_file(self.tmpfilepath)
        self.assertTrue("JSON must be dict with single key" in str(e.exception))

    def test_value_not_list(self):
        with open(self.tmpfilepath, "w") as f:
            json.dump({"key1": "a"}, f)
        with self.assertRaises(Exception) as e:
            self.encrypter.parse_json_file(self.tmpfilepath)
        self.assertTrue("value wrong datatype" in str(e.exception))

    def test_non_string_list(self):
        with open(self.tmpfilepath, "w") as f:
            json.dump({"key1": ['a', 1]}, f)
        with self.assertRaises(Exception) as e:
            self.encrypter.parse_json_file(self.tmpfilepath)
        self.assertTrue("list contains non-string values" in str(e.exception))

class EncrypterGetLatest(unittest.TestCase):

    def setUp(self):

        self.encrypter = Encrypter()

    @patch("encrypter.b")
    def test_get_latest(self, mock_boto_client):
        with self.assertRaises(Exception):
            self.encrypter.get_latest_image(("name", "test"), mock_boto_client.client)
        mock_boto_client.client.describe_images.assert_called()

    @patch("encrypter.b")
    def test_get_latest_client_unauthorised(self, mock_boto):

        mock_boto.client.describe_images = Mock(side_effect=ClientError(
            {'Error': {'Code': 'Unauthorized', 'Message': 'Not allowed'}}, 'DescribeImage'))

        with self.assertRaises(Exception) as e:
            self.encrypter.get_latest_image(("FilterName", "FilterValue"), mock_boto.client)
        self.assertTrue("failed" in str(e.exception) and len(self.encrypter.unprocessed) == 0)

    @patch("encrypter.b")
    def test_get_latest_client_invalid_parameter(self, mock_boto):

        mock_boto.client.describe_images = Mock(side_effect=ClientError(
            {'Error': {'Code': 'InvalidParameterValue', 'Message': 'Parameters invalid'}}, 'DescribeImage'))

        with self.assertRaises(Exception) as e:
            self.encrypter.get_latest_image(("FilterName", "FilterValue"), mock_boto.client)
        self.assertTrue("failed" in str(e.exception) and len(self.encrypter.unprocessed) == 1)

    @patch("encrypter.b")
    def test_get_latest_none(self, mock_boto_client):

        mock_boto_client.client.describe_images.return_value = {'Images': []}

        with self.assertRaises(Exception) as e:
            self.encrypter.get_latest_image(("FilterName", "FilterValue"), mock_boto_client.client)
        self.assertTrue("zero images returned by 'FilterName'" in str(e.exception))

    @patch("encrypter.b")
    def test_get_latest_one(self, mock_boto_client):

        returned_object = {'Images': [{'Name': 'TestName', 'ImageId': '1'}]}

        mock_boto_client.client.describe_images.return_value = returned_object

        result = self.encrypter.get_latest_image(("FilterName", "FilterValue"), mock_boto_client.client)
        self.assertEqual({'Name': 'TestName', 'ImageId': '1'}, result)

if __name__ == '__main__':
    unittest.main()