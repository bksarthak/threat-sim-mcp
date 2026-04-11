import unittest
from python.adapters.checkov import CheckovAdapter

class TestCheckovAdapter(unittest.TestCase):
    def test_parse_standard_output(self):
        mock_data = {
            "results": {
                "failed_checks": [
                    {
                        "resource": "aws_s3_bucket.prod_data",
                        "file_path": "/main.tf",
                        "file_line_range": [1, 5]
                    }
                ],
                "passed_checks": [
                    {
                        "resource": "aws_vpc.main",
                        "file_path": "/vpc.tf",
                        "file_line_range": [10, 15]
                    }
                ]
            }
        }
        
        adapter = CheckovAdapter(mock_data)
        adapter.parse()
        
        nodes = adapter.get_nodes()
        self.assertEqual(len(nodes), 2)
        
        node_ids = [n["id"] for n in nodes]
        self.assertIn("aws_s3_bucket.prod_data", node_ids)
        self.assertIn("aws_vpc.main", node_ids)

if __name__ == '__main__':
    unittest.main()
