@load policy/tuning/json-logs

redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_EPOCH;
redef Log::default_rotation_interval = 0secs;
