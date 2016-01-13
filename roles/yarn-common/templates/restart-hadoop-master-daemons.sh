#!/bin/bash

source {{ common['soft_link_base_path'] }}/hadoop/env.sh

{% raw %}
${HADOOP_HOME}/sbin/yarn-daemon.sh stop resourcemanager
${HADOOP_HOME}/sbin/yarn-daemon.sh start resourcemanager

#${HADOOP_HOME}/sbin/mr-jobhistory-daemon.sh stop historyserver
#${HADOOP_HOME}/sbin/mr-jobhistory-daemon.sh start historyserver

${HADOOP_HOME}/sbin/hadoop-daemon.sh stop namenode
${HADOOP_HOME}/bin/hadoop namenode -format -nonInteractive || true
${HADOOP_HOME}/sbin/hadoop-daemon.sh start namenode
{% endraw %}
