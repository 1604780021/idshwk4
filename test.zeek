@load base/frameworks/sumstats

event http_reply(c: connection, version: string, code: count, reason: string) 
{
    SumStats::observe("response", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
    if (code == 404) 
    {
        SumStats::observe("response404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
        SumStats::observe("responseUnique404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));
    }
}


event zeek_init() 
{
    local r1 = SumStats::Reducer($stream="response", $apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="response404", $apply=set(SumStats::SUM));
    local r3 = SumStats::Reducer($stream="responseUnique404", $apply=set(SumStats::UNIQUE));
    SumStats::create([$name="idshwk4", $epoch=10min, $reducers=set(r1, r2, r3), $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
        local res = result["response"];
        local res404 = result["response404"];
        local resuni404 = result["responseUnique404"];
        if (res404$sum > 2) 
        {
            if (res404$sum / res$sum > 0.2) 
            {
                if (resuni404$unique / res404$sum > 0.5) 
                {
                    print fmt(" %s is a scanner with %.0f scan attemps on %d urls", key$host, res404$sum, resuni404$unique);
                } 
            }
        }
    }]);
}
