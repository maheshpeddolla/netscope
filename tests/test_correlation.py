from netscope.engines.correlation_engine import correlate

sample = {

    "ethtool": {

        "findings": [

            {
                "severity": "warning",
                "message": "RX drops"
            }

        ]
    },

    "softnet": {

        "findings": [

            {
                "severity": "warning",
                "message": "CPU backlog drops"
            }

        ]
    },

    "nstat": {

        "findings": [

            {
                "severity": "warning",
                "message": "TCP retransmissions"
            }

        ]
    }

}

result = correlate(sample)

print(result)