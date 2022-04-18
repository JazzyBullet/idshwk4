@load base/frameworks/sumstats

event http_reply(c:connection, version: string, code: count, reason: string)
{
     SumStats::observe("all_resp", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
     if(cood == 404)
     {
         SumStats::observe("404_resp", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
         SumStats::observe("unique_404_resp", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));
     }
}

event zeek_init()
{
    local r_all = SumStats::Reducer($stream="all_resp", $apply=set(SumStats::SUM));
    local r_404 = SumStats::Reducer($stream="404_resp", $apply=set(SumStats::SUM));
    local r_unique_404 = SumStats::Reducer($stream="unique_404_resp", $apply=set(SumStats::UNIQUE));

    SumStats::create([
                        $name="zzy_hw4",
                        $epoch=10min,
                        $reducers=set(r_all, r_404, r_unique_404),
                        $epoch_result(ts:time, key:SumStats::Key, result: SumStats::Result) = 
                        {
                            local r1 = result["all_resp"];
                            local r2 = result["404_resp"];
                            local r3 = result["unique_404_resp"];
                            if(r2$sum > 2)
                            {
                                if(r2$sum / r1$sum > 0.2)
                                {
                                    if(r3$sum / r2$sum > 0.5)
                                    {
                                        print fmt("%s is a scanner with %.0f scan attemps on %d urls", key$host, r2$sum, r3$unique);
                                    }
                                }
                            }
                        }
                        ]);
}