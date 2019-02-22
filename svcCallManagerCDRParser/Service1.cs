using System;
using System.Collections.Generic;
using System.Data.Entity.Migrations;
using System.IO;
using System.Linq;
using System.ServiceProcess;

public partial class Service1 : ServiceBase
{
    //The main timer
    private System.Timers.Timer m_mainTimer;

    //How often to run the routine in milliseconds (seconds * 1000)
    private int scanInterval = 10 * 1000;

    //Service Specific Stuff
    private static string SourceCDRFolder = @"\\lsnjmonitor\cdr\";
    private static string ArchiveCDRFolder = @"\\lsnjmonitor\cdr\Archive\";
    private static string ExceptionCDRFolder = @"\\lsnjmonitor\cdr\Exceptions\";

    public Service1()
    {
        InitializeComponent();
    }

    protected override void OnStart(string[] args)
    {
        //Create the Main timer
        m_mainTimer = new System.Timers.Timer
        {
            //Set the timer interval
            Interval = scanInterval
        };
        //Dictate what to do when the event fires
        m_mainTimer.Elapsed += m_mainTimer_Elapsed;
        //Something to do with something, I forgot since it's been a while
        m_mainTimer.AutoReset = true;

#if DEBUG
#else
            m_mainTimer.Start(); //Start timer only in Release
#endif

        //Run 1st Tick Manually
        Routine();
    }

    public void OnDebug()
    {
        //Manually kick off the service when debugging
        OnStart(null);
    }

    protected override void OnStop()
    {
    }

    static void m_mainTimer_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
    {
        //Each interval run the UpdateUsers() function
        Routine();
    }

    private static void Routine()
    {
        Console.Beep(2000, 1000);

        var cdrFiles = Directory.EnumerateFiles(SourceCDRFolder, "cdr_*", SearchOption.TopDirectoryOnly);

        foreach (var cdrFile in cdrFiles)
        {
            var calls = new List<Call>();

            try
            {
                //Get the file info to check the creation date
                var info = new FileInfo(cdrFile);

                //Only parse files more than a minute old to prevent a chance to open an active file (currently being written to by the FTP server)
                if (info.CreationTime < DateTime.Now.AddMinutes(-1))
                {
                    //Read the line of the CDR file
                    var lines = File.ReadAllLines(cdrFile);

                    //Skip the 1st two lines of the file which are header rows
                    foreach (var line in lines.Skip(2))
                    {
                        var fields = line.Split(',');

                        if (fields.Length == 129)
                        {
                            //Create a call from the fields
                            var call = CreateCallFrom129Fields(fields);

                            //Add the call to the List<> of calls
                            calls.Add(call);
                        }
                        else if (fields.Length == 94)
                        {
                            //Create a call from the fields
                            var call = CreateCallFrom94Fields(fields);

                            //Add the call to the List<> of calls
                            calls.Add(call);
                        }
                    }

                    //Archive Process
                    var FilePath = info.DirectoryName;
                    var FileName = info.Name;

                    if (WriteCallsToDB(calls))
                    {
                        var archiveFolder = ArchiveCDRFolder + info.CreationTime.Year.ToString() + "-" + info.CreationTime.Month.ToString() + "-" + info.CreationTime.Day.ToString() + @"\";
                        var archiveFile = archiveFolder + FileName;
                        Directory.CreateDirectory(archiveFolder);
                        File.Move(cdrFile, archiveFile);
                    }
                    else
                    {
                        var exceptionFolder = ExceptionCDRFolder + info.CreationTime.Year.ToString() + "-" + info.CreationTime.Month.ToString() + "-" + info.CreationTime.Day.ToString() + @"\";
                        var exceptionFile = exceptionFolder + FileName;
                        Directory.CreateDirectory(exceptionFolder);
                        File.Move(cdrFile, exceptionFile);
                    }
                }
            }
            catch (Exception e) { Console.WriteLine(e); }
        }

        Console.Beep(4000, 1000);
    }

    private static Call CreateCallFrom129Fields(string[] fields)
    {
        //Convert the Cisco timestamp for dateTimeDisconnect to a normal DateTime
        var dt = new DateTime(1970, 1, 1).AddSeconds(Convert.ToInt32(fields[48]));

        //Create a Call object from the fields, using the dt above for dateTimeDisconnect
        var call = new Call
        {
            cdrRecordType = fields[0].ToLower().ToString(),
            globalCallID_callManagerId = fields[1].ToLower().ToString(),
            globalCallID_callId = fields[2].ToLower().ToString(),
            origLegCallIdentifier = fields[3].ToLower().ToString(),
            dateTimeOrigination = fields[4].ToLower().ToString(),
            origNodeId = fields[5].ToLower().ToString(),
            origSpan = fields[6].ToLower().ToString(),
            origIpAddr = fields[7].ToLower().ToString(),
            callingPartyNumber = fields[8].ToLower().ToString(),
            callingPartyUnicodeLoginUserID = fields[9].ToLower().ToString(),
            origCause_location = fields[10].ToLower().ToString(),
            origCause_value = fields[11].ToLower().ToString(),
            origPrecedenceLevel = fields[12].ToLower().ToString(),
            origMediaTransportAddress_IP = fields[13].ToLower().ToString(),
            origMediaTransportAddress_Port = fields[14].ToLower().ToString(),
            origMediaCap_payloadCapability = fields[15].ToLower().ToString(),
            origMediaCap_maxFramesPerPacket = fields[16].ToLower().ToString(),
            origMediaCap_g723BitRate = fields[17].ToLower().ToString(),
            origVideoCap_Codec = fields[18].ToLower().ToString(),
            origVideoCap_Bandwidth = fields[19].ToLower().ToString(),
            origVideoCap_Resolution = fields[20].ToLower().ToString(),
            origVideoTransportAddress_IP = fields[21].ToLower().ToString(),
            origVideoTransportAddress_Port = fields[22].ToLower().ToString(),
            origRSVPAudioStat = fields[23].ToLower().ToString(),
            origRSVPVideoStat = fields[24].ToLower().ToString(),
            destLegIdentifier = fields[25].ToLower().ToString(),
            destNodeId = fields[26].ToLower().ToString(),
            destSpan = fields[27].ToLower().ToString(),
            destIpAddr = fields[28].ToLower().ToString(),
            originalCalledPartyNumber = fields[29].ToLower().ToString(),
            finalCalledPartyNumber = fields[30].ToLower().ToString(),
            finalCalledPartyUnicodeLoginUserID = fields[31].ToLower().ToString(),
            destCause_location = fields[32].ToLower().ToString(),
            destCause_value = fields[33].ToLower().ToString(),
            destPrecedenceLevel = fields[34].ToLower().ToString(),
            destMediaTransportAddress_IP = fields[35].ToLower().ToString(),
            destMediaTransportAddress_Port = fields[36].ToLower().ToString(),
            destMediaCap_payloadCapability = fields[37].ToLower().ToString(),
            destMediaCap_maxFramesPerPacket = fields[38].ToLower().ToString(),
            destMediaCap_g723BitRate = fields[39].ToLower().ToString(),
            destVideoCap_Codec = fields[40].ToLower().ToString(),
            destVideoCap_Bandwidth = fields[41].ToLower().ToString(),
            destVideoCap_Resolution = fields[42].ToLower().ToString(),
            destVideoTransportAddress_IP = fields[43].ToLower().ToString(),
            destVideoTransportAddress_Port = fields[44].ToLower().ToString(),
            destRSVPAudioStat = fields[45].ToLower().ToString(),
            destRSVPVideoStat = fields[46].ToLower().ToString(),
            dateTimeConnect = fields[47].ToLower().ToString(),
            dateTimeDisconnect = dt,
            lastRedirectDn = fields[49].ToLower().ToString(),
            pkid = fields[50].ToLower().ToString(),
            originalCalledPartyNumberPartition = fields[51].ToLower().ToString(),
            callingPartyNumberPartition = fields[52].ToLower().ToString(),
            finalCalledPartyNumberPartition = fields[53].ToLower().ToString(),
            lastRedirectDnPartition = fields[54].ToLower().ToString(),
            duration = fields[55].ToLower().ToString(),
            origDeviceName = fields[56].ToLower().ToString(),
            destDeviceName = fields[57].ToLower().ToString(),
            origCallTerminationOnBehalfOf = fields[58].ToLower().ToString(),
            destCallTerminationOnBehalfOf = fields[59].ToLower().ToString(),
            origCalledPartyRedirectOnBehalfOf = fields[60].ToLower().ToString(),
            lastRedirectRedirectOnBehalfOf = fields[61].ToLower().ToString(),
            origCalledPartyRedirectReason = fields[62].ToLower().ToString(),
            lastRedirectRedirectReason = fields[63].ToLower().ToString(),
            destConversationId = fields[64].ToLower().ToString(),
            globalCallId_ClusterID = fields[65].ToLower().ToString(),
            joinOnBehalfOf = fields[66].ToLower().ToString(),
            comment = fields[67].ToLower().ToString(),
            authCodeDescription = fields[68].ToLower().ToString(),
            authorizationLevel = fields[69].ToLower().ToString(),
            clientMatterCode = fields[70].ToLower().ToString(),
            origDTMFMethod = fields[71].ToLower().ToString(),
            destDTMFMethod = fields[72].ToLower().ToString(),
            callSecuredStatus = fields[73].ToLower().ToString(),
            origConversationId = fields[74].ToLower().ToString(),
            origMediaCap_Bandwidth = fields[75].ToLower().ToString(),
            destMediaCap_Bandwidth = fields[76].ToLower().ToString(),
            authorizationCodeValue = fields[77].ToLower().ToString(),
            outpulsedCallingPartyNumber = fields[78].ToLower().ToString(),
            outpulsedCalledPartyNumber = fields[79].ToLower().ToString(),
            origIpv4v6Addr = fields[80].ToLower().ToString(),
            destIpv4v6Addr = fields[81].ToLower().ToString(),
            origVideoCap_Codec_Channel2 = fields[82].ToLower().ToString(),
            origVideoCap_Bandwidth_Channel2 = fields[83].ToLower().ToString(),
            origVideoCap_Resolution_Channel2 = fields[84].ToLower().ToString(),
            origVideoTransportAddress_IP_Channel2 = fields[85].ToLower().ToString(),
            origVideoTransportAddress_Port_Channel2 = fields[86].ToLower().ToString(),
            origVideoChannel_Role_Channel2 = fields[87].ToLower().ToString(),
            destVideoCap_Codec_Channel2 = fields[88].ToLower().ToString(),
            destVideoCap_Bandwidth_Channel2 = fields[89].ToLower().ToString(),
            destVideoCap_Resolution_Channel2 = fields[90].ToLower().ToString(),
            destVideoTransportAddress_IP_Channel2 = fields[91].ToLower().ToString(),
            destVideoTransportAddress_Port_Channel2 = fields[92].ToLower().ToString(),
            destVideoChannel_Role_Channel2 = fields[93].ToLower().ToString(),
            IncomingProtocolID = fields[94].ToLower().ToString(),
            IncomingProtocolCallRef = fields[95].ToLower().ToString(),
            OutgoingProtocolID = fields[96].ToLower().ToString(),
            OutgoingProtocolCallRef = fields[97].ToLower().ToString(),
            currentRoutingReason = fields[98].ToLower().ToString(),
            origRoutingReason = fields[99].ToLower().ToString(),
            lastRedirectingRoutingReason = fields[100].ToLower().ToString(),
            huntPilotPartition = fields[101].ToLower().ToString(),
            huntPilotDN = fields[102].ToLower().ToString(),
            calledPartyPatternUsage = fields[103].ToLower().ToString(),
            IncomingICID = fields[104].ToLower().ToString(),
            IncomingOrigIOI = fields[105].ToLower().ToString(),
            IncomingTermIOI = fields[106].ToLower().ToString(),
            OutgoingICID = fields[107].ToLower().ToString(),
            OutgoingOrigIOI = fields[108].ToLower().ToString(),
            OutgoingTermIOI = fields[109].ToLower().ToString(),
            outpulsedOriginalCalledPartyNumber = fields[110].ToLower().ToString(),
            outpulsedLastRedirectingNumber = fields[111].ToLower().ToString(),
            wasCallQueued = fields[112].ToLower().ToString(),
            totalWaitTimeInQueue = fields[113].ToLower().ToString(),
            callingPartyNumber_uri = fields[114].ToLower().ToString(),
            originalCalledPartyNumber_uri = fields[115].ToLower().ToString(),
            finalCalledPartyNumber_uri = fields[116].ToLower().ToString(),
            lastRedirectDn_uri = fields[117].ToLower().ToString(),
            mobileCallingPartyNumber = fields[118].ToLower().ToString(),
            finalMobileCalledPartyNumber = fields[119].ToLower().ToString(),
            origMobileDeviceName = fields[120].ToLower().ToString(),
            destMobileDeviceName = fields[121].ToLower().ToString(),
            origMobileCallDuration = fields[122].ToLower().ToString(),
            destMobileCallDuration = fields[123].ToLower().ToString(),
            mobileCallType = fields[124].ToLower().ToString(),
            originalCalledPartyPattern = fields[125].ToLower().ToString(),
            finalCalledPartyPattern = fields[126].ToLower().ToString(),
            lastRedirectingPartyPattern = fields[127].ToLower().ToString(),
            huntPilotPattern = fields[128].ToLower().ToString(),
            Year = dt.Year,
            Month = dt.Month,
            Day = dt.Day,
            Hour = dt.Hour,
            Minute = dt.Minute,
            DayOfWeek = dt.DayOfWeek,
        };

        return call;
    }

    private static Call CreateCallFrom94Fields(string[] fields)
    {
        //Convert the Cisco timestamp for dateTimeDisconnect to a normal DateTime
        var dt = new DateTime(1970, 1, 1).AddSeconds(Convert.ToInt32(fields[48]));

        //Create a Call object from the fields, using the dt above for dateTimeDisconnect
        var call = new Call
        {
            cdrRecordType = fields[0].ToLower().ToString(),
            globalCallID_callManagerId = fields[1].ToLower().ToString(),
            globalCallID_callId = fields[2].ToLower().ToString(),
            origLegCallIdentifier = fields[3].ToLower().ToString(),
            dateTimeOrigination = fields[4].ToLower().ToString(),
            origNodeId = fields[5].ToLower().ToString(),
            origSpan = fields[6].ToLower().ToString(),
            origIpAddr = fields[7].ToLower().ToString(),
            callingPartyNumber = fields[8].ToLower().ToString(),
            callingPartyUnicodeLoginUserID = fields[9].ToLower().ToString(),
            origCause_location = fields[10].ToLower().ToString(),
            origCause_value = fields[11].ToLower().ToString(),
            origPrecedenceLevel = fields[12].ToLower().ToString(),
            origMediaTransportAddress_IP = fields[13].ToLower().ToString(),
            origMediaTransportAddress_Port = fields[14].ToLower().ToString(),
            origMediaCap_payloadCapability = fields[15].ToLower().ToString(),
            origMediaCap_maxFramesPerPacket = fields[16].ToLower().ToString(),
            origMediaCap_g723BitRate = fields[17].ToLower().ToString(),
            origVideoCap_Codec = fields[18].ToLower().ToString(),
            origVideoCap_Bandwidth = fields[19].ToLower().ToString(),
            origVideoCap_Resolution = fields[20].ToLower().ToString(),
            origVideoTransportAddress_IP = fields[21].ToLower().ToString(),
            origVideoTransportAddress_Port = fields[22].ToLower().ToString(),
            origRSVPAudioStat = fields[23].ToLower().ToString(),
            origRSVPVideoStat = fields[24].ToLower().ToString(),
            destLegIdentifier = fields[25].ToLower().ToString(),
            destNodeId = fields[26].ToLower().ToString(),
            destSpan = fields[27].ToLower().ToString(),
            destIpAddr = fields[28].ToLower().ToString(),
            originalCalledPartyNumber = fields[29].ToLower().ToString(),
            finalCalledPartyNumber = fields[30].ToLower().ToString(),
            finalCalledPartyUnicodeLoginUserID = fields[31].ToLower().ToString(),
            destCause_location = fields[32].ToLower().ToString(),
            destCause_value = fields[33].ToLower().ToString(),
            destPrecedenceLevel = fields[34].ToLower().ToString(),
            destMediaTransportAddress_IP = fields[35].ToLower().ToString(),
            destMediaTransportAddress_Port = fields[36].ToLower().ToString(),
            destMediaCap_payloadCapability = fields[37].ToLower().ToString(),
            destMediaCap_maxFramesPerPacket = fields[38].ToLower().ToString(),
            destMediaCap_g723BitRate = fields[39].ToLower().ToString(),
            destVideoCap_Codec = fields[40].ToLower().ToString(),
            destVideoCap_Bandwidth = fields[41].ToLower().ToString(),
            destVideoCap_Resolution = fields[42].ToLower().ToString(),
            destVideoTransportAddress_IP = fields[43].ToLower().ToString(),
            destVideoTransportAddress_Port = fields[44].ToLower().ToString(),
            destRSVPAudioStat = fields[45].ToLower().ToString(),
            destRSVPVideoStat = fields[46].ToLower().ToString(),
            dateTimeConnect = fields[47].ToLower().ToString(),
            dateTimeDisconnect = dt,
            lastRedirectDn = fields[49].ToLower().ToString(),
            pkid = fields[50].ToLower().ToString(),
            originalCalledPartyNumberPartition = fields[51].ToLower().ToString(),
            callingPartyNumberPartition = fields[52].ToLower().ToString(),
            finalCalledPartyNumberPartition = fields[53].ToLower().ToString(),
            lastRedirectDnPartition = fields[54].ToLower().ToString(),
            duration = fields[55].ToLower().ToString(),
            origDeviceName = fields[56].ToLower().ToString(),
            destDeviceName = fields[57].ToLower().ToString(),
            origCallTerminationOnBehalfOf = fields[58].ToLower().ToString(),
            destCallTerminationOnBehalfOf = fields[59].ToLower().ToString(),
            origCalledPartyRedirectOnBehalfOf = fields[60].ToLower().ToString(),
            lastRedirectRedirectOnBehalfOf = fields[61].ToLower().ToString(),
            origCalledPartyRedirectReason = fields[62].ToLower().ToString(),
            lastRedirectRedirectReason = fields[63].ToLower().ToString(),
            destConversationId = fields[64].ToLower().ToString(),
            globalCallId_ClusterID = fields[65].ToLower().ToString(),
            joinOnBehalfOf = fields[66].ToLower().ToString(),
            comment = fields[67].ToLower().ToString(),
            authCodeDescription = fields[68].ToLower().ToString(),
            authorizationLevel = fields[69].ToLower().ToString(),
            clientMatterCode = fields[70].ToLower().ToString(),
            origDTMFMethod = fields[71].ToLower().ToString(),
            destDTMFMethod = fields[72].ToLower().ToString(),
            callSecuredStatus = fields[73].ToLower().ToString(),
            origConversationId = fields[74].ToLower().ToString(),
            origMediaCap_Bandwidth = fields[75].ToLower().ToString(),
            destMediaCap_Bandwidth = fields[76].ToLower().ToString(),
            authorizationCodeValue = fields[77].ToLower().ToString(),
            outpulsedCallingPartyNumber = fields[78].ToLower().ToString(),
            outpulsedCalledPartyNumber = fields[79].ToLower().ToString(),
            origIpv4v6Addr = fields[80].ToLower().ToString(),
            destIpv4v6Addr = fields[81].ToLower().ToString(),
            origVideoCap_Codec_Channel2 = fields[82].ToLower().ToString(),
            origVideoCap_Bandwidth_Channel2 = fields[83].ToLower().ToString(),
            origVideoCap_Resolution_Channel2 = fields[84].ToLower().ToString(),
            origVideoTransportAddress_IP_Channel2 = fields[85].ToLower().ToString(),
            origVideoTransportAddress_Port_Channel2 = fields[86].ToLower().ToString(),
            origVideoChannel_Role_Channel2 = fields[87].ToLower().ToString(),
            destVideoCap_Codec_Channel2 = fields[88].ToLower().ToString(),
            destVideoCap_Bandwidth_Channel2 = fields[89].ToLower().ToString(),
            destVideoCap_Resolution_Channel2 = fields[90].ToLower().ToString(),
            destVideoTransportAddress_IP_Channel2 = fields[91].ToLower().ToString(),
            destVideoTransportAddress_Port_Channel2 = fields[92].ToLower().ToString(),
            destVideoChannel_Role_Channel2 = fields[93].ToLower().ToString(),
            Year = dt.Year,
            Month = dt.Month,
            Day = dt.Day,
            Hour = dt.Hour,
            Minute = dt.Minute,
            DayOfWeek = dt.DayOfWeek,
        };

        return call;
    }

    private static void WriteCallToDB(Call call)
    {
        try
        {
            using (var db = new CallSQLContext())
            {
                var existing = db.Calls.FirstOrDefault(c => c.pkid == call.pkid);

                if (existing == null)
                {
                    db.Calls.Add(call);
                    db.SaveChanges();
                }
            }
        }
        catch (Exception e) { Console.WriteLine(e); }
    }

    private static bool WriteCallsToDB(List<Call> calls)
    {
        try
        {
            using (var db = new CallSQLContext())
            {
                foreach (var call in calls)
                {
                    var existing = db.Calls.FirstOrDefault(c => c.dateTimeDisconnect == call.dateTimeDisconnect && c.callingPartyNumber == call.callingPartyNumber && c.originalCalledPartyNumber == call.originalCalledPartyNumber && c.finalCalledPartyNumber == call.finalCalledPartyNumber);

                    if (existing == null)
                    {
                        db.Calls.AddOrUpdate(call);
                        db.SaveChanges();
                    }
                }

                return true;
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            File.AppendAllText(SourceCDRFolder + "errors.log", e.ToString());
            return false;
        }
    }
}