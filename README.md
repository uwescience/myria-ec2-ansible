# myria-ec2-ansible
ansible file to deploy myria to ec2
# Instructions to Set up a Myria cluster on EC2

 Ansible is a configuration management tool that manages machines over the SSH protocol.Once Ansible is installed, it will not add a database, and there will be no daemons to start or keep running. You only need to install it on one machine (which could easily be a laptop) and it can manage an entire fleet of remote machines from that central point.
For the purposes of setting up MyriaX on EC2, we assume you are using your laptop as the 'Control Machine'. You could set it up on a EC2 instance for managing your EC2 deployed cluster as well.

*  __Setting up Ansible on Control Machine__
   Ansible documentation provided details on [installation]( http://docs.ansible.com/ansible/intro_installation.html#installing-     the-control-machine, "Installation").
   If your control machine is a Mac, the preferred way of installation is via `pip`. [Install via pip]( http://docs.ansible.com/ansible/intro_installation.html#latest-releases-via-pip). You can also use your native package manager (e.g., `brew` on a Mac, `apt-get` on Debian/Ubuntu, `yum` on Red Hat/CentOS) to install Ansible.

   Note that the wrapper script `myria-deploy` tries to install Ansible for you via `pip` (which will still prompt you for your password since it requires root privileges). You should only need to manually install Ansible if this fails.

*  __AWS account information__
   Ansible provides a number of core modules for AWS. We use several of these modules to setup MyriaX on AWS. The requirments for this are minimal.
   Authentication with the AWS-related modules is handled by either specifying your access and secret key as ENV variables or module arguments. You need access key ID and secret for AWS. Here is a [link to AWS documentation](http://docs.aws.amazon.com/general/latest/gr/managing-aws-access-keys.html), on how to get the access key and secret. Once you have these values, set them up as ENV variables:

    export AWS_ACCESS_KEY_ID='AK123'

    export AWS_SECRET_ACCESS_KEY='abc123'

  Note that if you have the Python `boto` module or the AWS CLI configured, you do not need these environment variables.

*  __Deploy__
   Run the wrapper script `myria-deploy`, which will check for dependencies, install Ansible, and run the playbook:
     ./myria-deploy --profile myria --key-pair tdbaker --private-key-file ~/.ssh/tdbaker.pem
