#!/bin/bash

source {{ common['soft_link_base_path'] }}/hadoop/env.sh

{% raw %}
${HADOOP_HOME}/sbin/yarn-daemon.sh stop nodemanager
${HADOOP_HOME}/sbin/yarn-daemon.sh start nodemanager

${HADOOP_HOME}/sbin/hadoop-daemon.sh stop datanode
${HADOOP_HOME}/sbin/hadoop-daemon.sh start datanode
{% endraw %}
