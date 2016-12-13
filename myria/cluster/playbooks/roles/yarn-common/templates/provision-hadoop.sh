#!/bin/bash

SCRIPT_DIR={{ hadoop_home }}/pbin
APP_USER={{ myria_user }}
HADOOP_USER={{ hadoop_user }}
HADOOP_GROUP={{ hadoop_group }}
HADOOP_HOME={{ hadoop_home }}

{% raw %}
set -e

echo "Installing hadoop ..."
source ${SCRIPT_DIR}/hadoop-config.sh

if [ -e ${ENV_CONFIG} ]
then
  echo "env.sh already exists"
else
  echo "creating hadoop environment script... "
  cat <<EOF > ${ENV_CONFIG}
export JAVA_HOME=$JAVA_HOME
export HADOOP_HOME=${HADOOP_HOME}
export HADOOP_MAPRED_HOME=${HADOOP_HOME}
export HADOOP_COMMON_HOME=${HADOOP_HOME}
export HADOOP_HDFS_HOME=${HADOOP_HOME}
export YARN_HOME=${HADOOP_HOME}
export HADOOP_CONF_DIR=${HADOOP_HOME}/etc/hadoop
export YARN_CONF_DIR=${HADOOP_HOME}/etc/hadoop
export YARN_ROOT_LOGGER=${YARN_LOG_LEVEL},console
export HADOOP_LOG_DIR=${HADOOP_LOG_DIR}
export YARN_LOG_DIR=${HADOOP_LOG_DIR}
EOF
fi

echo "fixing permissions ... "
# Needed to enable cgroups
chown -R -H root:root ${HADOOP_HOME}
chown root:${HADOOP_GROUP} ${CONTAINER_EXECUTOR}
chown root:${HADOOP_GROUP} ${CONTAINER_EXECUTOR_CFG}
chmod 6050 ${CONTAINER_EXECUTOR}
chmod 0400 ${CONTAINER_EXECUTOR_CFG}
# Needed for Hadoop daemon and application logs
mkdir -p ${HADOOP_LOG_DIR}
chmod 777 ${HADOOP_LOG_DIR}
# Needed for NameNode data
mkdir -p ${HADOOP_HOME}/tmp
chmod 777 ${HADOOP_HOME}/tmp
# Needed for HDFS permissions to work
groupadd -f supergroup
usermod -a -G supergroup ${HADOOP_USER}
usermod -a -G supergroup ${APP_USER}

echo "done installing hadoop environment"
{% endraw %}
