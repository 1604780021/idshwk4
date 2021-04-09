@load base/frameworks/sumstats
global allresponse: count = 0;

event http_reply(c: connection, version: string, code: count, reason: string)
{
    ++allresponse;
    if (code==404)
        SumStats::observe("http.404requests.unique", [$host=c$id$orig_h], [$str=reason]);
}

event zeek_init()
{
    local r1 = SumStats::Reducer($stream="http.404requests.unique", $apply=set(SumStats::UNIQUE,SumStats::SUM));
    SumStats::create([$name="idshwk4",
                      $epoch=10mins,
                      $reducers=set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                      {
                        local r = result["http.404requests.unique"];
                        if(r$num>2)
                        {
                            if(r$num/allresponse>0.2)
                            {
                                if(r$unique/r$num>0.5)
                                    print fmt("%s is a scanner with %d scan attempts on %d urls", key$host, r$num, r$unique); 
                            }
                        }
                      }
                    ]);
}