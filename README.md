# myria-ec2-ansible
Ansible playbook to deploy Myria on EC2
## How to set up a Myria cluster on EC2

Ansible is a configuration management tool that manages machines via the SSH protocol. Ansible does not require a database or any background processes to function on the control machine, and installs no software on the managed machines. You only need to install it on a single "control machine" (which could easily be a laptop) and it can manage an entire fleet of remote machines from that central point.
For the purpose of setting up Myria on EC2, we assume you are using your laptop as the control machine. You could also use an EC2 instance as a control machine. Any modern Unix should work as the control machine, although only Ubuntu and Mac OS X have been tested. Windows is not supported, since Ansible does not support it.

### __(Optional) Set up Ansible on a control machine__
You do not need to install Ansible before running the `myria-deploy` script, since the script will install it for you, but in case you have issues with the script's Ansible installation, you can install it yourself and the script will use your installation.
Follow the Ansible installation [instructions]( http://docs.ansible.com/ansible/intro_installation.html#installing-the-control-machine, "Installation").
If your control machine is a Mac, the preferred method of installation is via `pip` ([instructions]( http://docs.ansible.com/ansible/intro_installation.html#latest-releases-via-pip )). You can also use your native package manager (e.g., `brew` on a Mac, `apt-get` on Debian/Ubuntu, `yum` on Red Hat/CentOS) to install Ansible. (Note that El Capitan users have reported that `sudo pip install` with the system Python installation fails with filesystem permission errors, so using a package manager like Homebrew is recommended on El Capitan.)

### __Configure AWS account information__
Ansible provides a number of core modules for AWS, which we use to deploy Myria on EC2. These modules require your AWS credentials ("Access Key ID" and "Secret Key") to be configured on the control machine. Here is a [link to AWS documentation](http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html) on how to obtain an AWS access key ID and secret key. Once you have these values, you can use them to configure the AWS CLI. (Note that an IAM user account must have the following permissions to install Myria: `ec2:CreateKeyPair`, `ec2:DescribeKeyPairs`, `ec2:RunInstances`, `ec2:DescribeInstances`, `ec2:DescribeInstanceStatus`.)

### __Install the AWS CLI__
The `myria-deploy` script that you'll be running to deploy Myria on EC2 requires the AWS CLI to be installed. Follow the instructions in the [AWS CLI documentation](http://docs.aws.amazon.com/cli/latest/userguide/installing.html) to install the CLI and configure it with the AWS credentials you obtained in the previous step.

### __Deploy your Myria cluster__
Run the wrapper script `myria-deploy`, which will check for missing dependencies, launch EC2 instances using your AWS credentials, and deploy Myria on the instances:

```
./myria-deploy --verbose
```

To see a list of all options, run

```
./myria-deploy --help
```
When the `myria-deploy` script has successfully deployed Myria, it will print the URL of the `myria-web` instance running on the cluster to the console. You can point your browser to this URL to compose and run queries in the query editor (with syntax highlighting), view query plans in graphical and JSON form, profile running queries, and browse datasets and historical queries. You can read more about `myria-web` [here](http://myria.cs.washington.edu/docs/myria-web/index.html).

Note that the `myria-deploy` script can be run in isolation, without cloning this repo (it will clone the repo to a temporary location if it's not already present). The script itself can be directly downloaded [here](https://raw.githubusercontent.com/uwescience/myria-ec2-ansible/reef/myria-deploy).
