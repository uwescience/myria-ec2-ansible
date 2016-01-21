# myria-ec2-ansible
Ansible playbook to deploy Myria on EC2
## How to set up a Myria cluster on EC2

 Ansible is a configuration management tool that manages machines via the SSH protocol. Once Ansible is installed, it will not add a database, and there will be no daemons to start or keep running. You only need to install it on one machine (which could easily be a laptop) and it can manage an entire fleet of remote machines from that central point.
For the purposes of setting up Myria on EC2, we assume you are using your laptop as the 'Control Machine'. You could set it up on an EC2 instance as well.

### __Set up Ansible on a control machine__
Follow the Ansible installation [instructions]( http://docs.ansible.com/ansible/intro_installation.html#installing-the-control-machine, "Installation").
If your control machine is a Mac, the preferred way of installation is via `pip` ([instructions]( http://docs.ansible.com/ansible/intro_installation.html#latest-releases-via-pip )). You can also use your native package manager (e.g., `brew` on a Mac, `apt-get` on Debian/Ubuntu, `yum` on Red Hat/CentOS) to install Ansible.

Note that the wrapper script `myria-deploy` tries to install Ansible for you via `pip` (which will still prompt you for your password since it requires root privileges). You should only need to manually install Ansible if this fails.

### __Configure AWS account information__
Ansible provides a number of core modules for AWS. We use several of these modules to deploy Myria on AWS. These modules require your AWS account information to be configured using either environment variables, module arguments, or `boto` config files. Here is a [link to AWS documentation](http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html) on how to obtain an AWS access key ID and secret key. Once you have these values, you can export them as environment variables:

```
export AWS_ACCESS_KEY_ID='AK123'
export AWS_SECRET_ACCESS_KEY='abc123'
```
Note that if you have configured the Python `boto` module or the AWS CLI, you do not need these environment variables.

### __Deploy your Myria cluster__
Run the wrapper script `myria-deploy`, which will check for dependencies, install Ansible, and run the playbook:

```
./myria-deploy --profile myria --key-pair tdbaker --private-key-file ~/.ssh/tdbaker.pem
```
Note that the `myria-deploy` script can be run in isolation, without cloning this repo. It will clone the repo to a temporary location if it's not already present. The script itself can be downloaded from

```
https://raw.githubusercontent.com/uwescience/myria-ec2-ansible/reef/myria-deploy
```
