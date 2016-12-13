set -e

export JAVA_HOME={{ java_home }}
export HADOOP_HOME={{ hadoop_home }}

#hadoop home is here irrespective of version
export CORE_DEFAULT=${HADOOP_HOME}/etc/hadoop/core-default.xml
export CORE_SITE=${HADOOP_HOME}/etc/hadoop/core-site.xml
export YARN_DEFAULT=${HADOOP_HOME}/etc/hadoop/yarn-default.xml
export CONTAINER_EXECUTOR=${HADOOP_HOME}/bin/container-executor
export CONTAINER_EXECUTOR_CFG=${HADOOP_HOME}/etc/hadoop/container-executor.cfg
export YARN_SITE=${HADOOP_HOME}/etc/hadoop/yarn-site.xml
export MAPRED_SITE=${HADOOP_HOME}/etc/hadoop/mapred-site.xml
export ENV_CONFIG=${HADOOP_HOME}/env.sh
export YARN_LOG_LEVEL={{ CLUSTER_LOG_LEVEL }}
export HADOOP_LOG_DIR={{ hadoop_log_dir }}
