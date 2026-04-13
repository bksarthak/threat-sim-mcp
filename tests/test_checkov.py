import unittest
from unittest.mock import patch, mock_open
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

    @patch("os.path.exists")
    @patch("python.adapters.checkov.hcl2.load")
    @patch("builtins.open", new_callable=mock_open)
    def test_parse_with_edges(self, mock_op, mock_hcl2_load, mock_exists):
        mock_exists.return_value = True
        mock_data = {
            "results": {
                "failed_checks": [
                    {
                        "resource": "aws_instance.web",
                        "file_path": "main.tf",
                    },
                    {
                        "resource": "aws_security_group.web_sg",
                        "file_path": "main.tf",
                    }
                ]
            }
        }
        
        # Mock AST representing aws_instance.web referencing aws_security_group.web_sg
        mock_hcl2_load.return_value = {
            "resource": [
                {
                    "aws_instance": {
                        "web": {
                            "vpc_security_group_ids": ["${aws_security_group.web_sg.id}"]
                        }
                    }
                }
            ]
        }
        
        adapter = CheckovAdapter(mock_data, target_dir="/fake/dir")
        adapter.parse()
        
        edges = adapter.get_edges()
        self.assertEqual(len(edges), 1)
        self.assertEqual(edges[0]["from_node"], "aws_instance.web")
        self.assertEqual(edges[0]["to_node"], "aws_security_group.web_sg")
        self.assertEqual(edges[0]["type"], "references")

if __name__ == '__main__':
    unittest.main()
