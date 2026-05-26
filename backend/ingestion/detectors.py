# backend.ingestion.configs

FAILED_LOGINS_DETECTOR = {
    "name": "failed-logins-anomaly",
    "description": "Detects anomalies in failed SSH login attempts",
    "time_field": "timestamp",
    "indices": ["wazuh-alerts-*"],
    "filter_query": {
        "bool": {
            "must_not": {"term": {"rule.groups": "authentication_success"}}
        }
    },
    "detection_interval": {"period": {"interval": 1, "unit": "Minutes"}},
    "window_delay":        {"period": {"interval": 1, "unit": "Minutes"}},
    "feature_attributes": [
        {
            "feature_name": "failed-logins-srcip",
            "feature_enabled": True,
            "aggregation_query": {
                "failed_logins_srcip": {"value_count": {"field": "data.srcip"}}
            }
        },
        {
            "feature_name": "failed-logins-agentip",
            "feature_enabled": True,
            "aggregation_query": {
                "failed_logins_agentip": {"value_count": {"field": "agent.ip"}}
            }
        }
    ]
}

LINUX_RESOURCE_DETECTOR = {
    "name": "linux-resource-utilization-anomaly",
    "description": "Detects CPU and memory anomalies on Linux endpoints",
    "time_field": "timestamp",
    "indices": ["wazuh-alerts-*"],
    "detection_interval": {"period": {"interval": 1, "unit": "Minutes"}},
    "window_delay":        {"period": {"interval": 1, "unit": "Minutes"}},
    "feature_attributes": [
        {
            "feature_name": "cpu-usage-avg",
            "feature_enabled": True,
            "aggregation_query": {"cpu_usage_avg": {"avg": {"field": "data.cpu_usage_%"}}}
        },
        {
            "feature_name": "cpu-usage-max",
            "feature_enabled": True,
            "aggregation_query": {"cpu_usage_max": {"max": {"field": "data.cpu_usage_%"}}}
        },
        {
            "feature_name": "memory-usage-avg",
            "feature_enabled": True,
            "aggregation_query": {"memory_usage_avg": {"avg": {"field": "data.memory_usage_%"}}}
        },
        {
            "feature_name": "memory-usage-max",
            "feature_enabled": True,
            "aggregation_query": {"memory_usage_max": {"max": {"field": "data.memory_usage_%"}}}
        }
    ]
}