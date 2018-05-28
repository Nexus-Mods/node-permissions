{
    "targets": [
        {
            "target_name": "winperm",
            "includes": [
                "auto.gypi"
            ],
	    "conditions": [
		    ['OS=="win"', {
			    "sources": [
				    "src_win/permissions.cpp"
			    ],
		    }]
	    ],
            "include_dirs": [
            ],
            "libraries": [
            ],
            "cflags!": ["-fno-exceptions"],
            "cflags_cc!": ["-fno-exceptions"],
            "defines": [
                "UNICODE",
                "_UNICODE"
            ],
            "msvs_settings": {
                "VCCLCompilerTool": {
                    "ExceptionHandling": 1
                }
            }
        }
    ],
    "includes": [
        "auto-top.gypi"
    ]
}
