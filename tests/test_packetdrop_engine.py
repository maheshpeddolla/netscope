from netscope.diagnose.packetdrop_engine import diagnose

sample = {

    "softnet": {

        "available": True,

        "cpus": [

            {
                "cpu": 0,
                "dropped": 105,
                "time_squeeze": 7
            }

        ]

    },

    "nstat": {

        "available": True,

        "statistics": {

            "TcpRetransSegs": 240

        }

    },

    "ethtool": {

        "available": True,

        "interfaces": [

            {

                "name": "eth0",

                "statistics": {

                    "rx_dropped": 0

                }

            }

        ]

    }

}

result = diagnose(sample)

print()

print(result)