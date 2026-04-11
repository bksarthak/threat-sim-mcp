Output demo.gif

Require echo
Require sleep

Set FontSize 15
Set Width 1200
Set Height 700
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set Margin 20
Set MarginFill "#674EFF"
Set BorderRadius 10

# Hide the setup
Hide
Type "chmod +x ./mock_demo.sh"
Enter
Type "alias gemini='./mock_demo.sh'"
Enter
Type "cat << 'EOF' > .threatmodel.json"
Enter
Type '{'
Enter
Type '  "category": "Elevation of Privilege",'
Enter
Type '  "node": "internal-financial-records-2026",'
Enter
Type '  "mitigation": "Enforce IMDSv2 on the Web Server EC2 instance and remove wildcard S3 permissions from the IAM role."'
Enter
Type '}'
Enter
Type "EOF"
Enter
Type "clear"
Enter
Show

# The visual execution
Sleep 1.5s
Type "gemini --mcp threat-sim 'Parse ./examples/complex-lateral-movement. If an attacker breaches the internet-facing ALB... map the access paths to the data lake.'"
Sleep 1s
Enter
Sleep 18s

Type "cat .threatmodel.json"
Sleep 1.5s
Enter
Sleep 6s
