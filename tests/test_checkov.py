import unittest
from unittest.mock import patch, mock_open
from python.adapters.checkov import CheckovAdapter
from python.graph.pathfinder import Pathfinder

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
    def test_parse_with_edges_and_pathfinder(self, mock_op, mock_hcl2_load, mock_exists):
        mock_exists.return_value = True
        mock_data = {
            "results": {
                "failed_checks": [
                    {"resource": "aws_lb.web_alb", "file_path": "main.tf"},
                    {"resource": "aws_security_group.alb_sg", "file_path": "main.tf"},
                    {"resource": "aws_security_group.ec2_sg", "file_path": "main.tf"},
                    {"resource": "aws_instance.web_server", "file_path": "main.tf"},
                    {"resource": "aws_iam_role.web_role", "file_path": "main.tf"},
                    {"resource": "aws_iam_role_policy.s3_wild", "file_path": "main.tf"},
                    {"resource": "aws_s3_bucket.data_lake", "file_path": "main.tf"},
                ]
            }
        }

        mock_hcl2_load.return_value = {
            "resource": [
                {"aws_lb": {"web_alb": {"security_groups": ["${aws_security_group.alb_sg.id}"]}}},
                {"aws_security_group": {"ec2_sg": {"ingress": [{"security_groups": ["${aws_security_group.alb_sg.id}"]}]}}},
                {"aws_instance": {"web_server": {"vpc_security_group_ids": ["${aws_security_group.ec2_sg.id}"], "iam_instance_profile": "aws_iam_role.web_role"}}},
                {"aws_iam_role_policy": {"s3_wild": {"role": "${aws_iam_role.web_role.id}", "policy": '{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}'}}},
            ]
        }

        adapter = CheckovAdapter(mock_data, target_dir="/fake/dir")
        adapter.parse()

        edges = adapter.get_edges()
        self.assertTrue(any(e["source"] == "aws_lb.web_alb" and e["target"] == "aws_security_group.alb_sg" for e in edges))
        self.assertTrue(any(e["source"] == "aws_security_group.alb_sg" and e["target"] == "aws_security_group.ec2_sg" and e["type"] == "network_ingress" for e in edges))
        self.assertTrue(any(e["source"] == "aws_iam_role.web_role" and e["target"] == "aws_iam_role_policy.s3_wild" and e["type"] == "iam_policy_grant" for e in edges))
        self.assertTrue(any(e["source"] == "aws_iam_role_policy.s3_wild" and e["target"] == "aws_s3_bucket.data_lake" and e["type"] == "wildcard_access" for e in edges))

        pf = Pathfinder(adapter.get_graph_dict())
        red_res = pf.find_all_attack_paths("aws_lb.web_alb", "aws_s3_bucket.data_lake")
        self.assertTrue(red_res["paths_exist"])
        self.assertGreaterEqual(red_res["count"], 1)

        blue_res = pf.simulate_access_path(
            "aws_lb.web_alb",
            "aws_s3_bucket.data_lake",
            cut_edge_from="aws_iam_role_policy.s3_wild",
            cut_edge_to="aws_s3_bucket.data_lake",
        )
        self.assertFalse(blue_res["path_exists"])
        self.assertTrue(blue_res["mitigation_successful"])

    @patch("os.path.exists")
    @patch("python.adapters.checkov.hcl2.load")
    @patch("builtins.open", new_callable=mock_open)
    def test_sibling_prefix_traversal_blocked(self, mock_op, mock_hcl2_load, mock_exists):
        mock_exists.return_value = True
        mock_data = {
            "results": {
                "failed_checks": [
                    {"resource": "aws_s3_bucket.secret", "file_path": "../dir_secret/main.tf"}
                ]
            }
        }
        adapter = CheckovAdapter(mock_data, target_dir="/fake/dir")
        adapter.parse()
        mock_hcl2_load.assert_not_called()

if __name__ == '__main__':
    unittest.main()
