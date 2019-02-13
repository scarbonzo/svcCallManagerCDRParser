﻿using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

public class Call
{
    //Supplemental Fields
    public int Year { get; set; }
    public int Month { get; set; }
    public int Day { get; set; }
    public int Hour { get; set; }
    public int Minute { get; set; }
    public DayOfWeek DayOfWeek { get; set; }

    //Native CDR Fields
    [Key]
    public string pkid { get; set; }
    public string cdrRecordType { get; set; }
    public string globalCallID_callManagerId { get; set; }
    public string globalCallID_callId { get; set; }
    public string origLegCallIdentifier { get; set; }
    public string dateTimeOrigination { get; set; }
    public string origNodeId { get; set; }
    public string origSpan { get; set; }
    public string origIpAddr { get; set; }
    [Index]
    [Index("Unique", IsUnique = true, Order = 1)]
    [MaxLength(64)]
    public string callingPartyNumber { get; set; }
    public string callingPartyUnicodeLoginUserID { get; set; }
    public string origCause_location { get; set; }
    [Index]
    [MaxLength(64)]
    public string origCause_value { get; set; }
    public string origPrecedenceLevel { get; set; }
    public string origMediaTransportAddress_IP { get; set; }
    public string origMediaTransportAddress_Port { get; set; }
    public string origMediaCap_payloadCapability { get; set; }
    public string origMediaCap_maxFramesPerPacket { get; set; }
    public string origMediaCap_g723BitRate { get; set; }
    public string origVideoCap_Codec { get; set; }
    public string origVideoCap_Bandwidth { get; set; }
    public string origVideoCap_Resolution { get; set; }
    public string origVideoTransportAddress_IP { get; set; }
    public string origVideoTransportAddress_Port { get; set; }
    public string origRSVPAudioStat { get; set; }
    public string origRSVPVideoStat { get; set; }
    public string destLegIdentifier { get; set; }
    public string destNodeId { get; set; }
    public string destSpan { get; set; }
    public string destIpAddr { get; set; }
    [Index]
    [Index("Unique", IsUnique = true, Order = 2)]
    [MaxLength(64)]
    public string originalCalledPartyNumber { get; set; }
    [Index]
    [Index("Unique", IsUnique = true, Order = 3)]
    [MaxLength(64)]
    public string finalCalledPartyNumber { get; set; }
    public string finalCalledPartyUnicodeLoginUserID { get; set; }
    public string destCause_location { get; set; }
    [Index]
    [MaxLength(64)]
    public string destCause_value { get; set; }
    public string destPrecedenceLevel { get; set; }
    public string destMediaTransportAddress_IP { get; set; }
    public string destMediaTransportAddress_Port { get; set; }
    public string destMediaCap_payloadCapability { get; set; }
    public string destMediaCap_maxFramesPerPacket { get; set; }
    public string destMediaCap_g723BitRate { get; set; }
    public string destVideoCap_Codec { get; set; }
    public string destVideoCap_Bandwidth { get; set; }
    public string destVideoCap_Resolution { get; set; }
    public string destVideoTransportAddress_IP { get; set; }
    public string destVideoTransportAddress_Port { get; set; }
    public string destRSVPAudioStat { get; set; }
    public string destRSVPVideoStat { get; set; }
    public string dateTimeConnect { get; set; }
    [Index("Unique", IsUnique = true, Order = 4)]
    public DateTime dateTimeDisconnect { get; set; }
    public string lastRedirectDn { get; set; }
    public string originalCalledPartyNumberPartition { get; set; }
    public string callingPartyNumberPartition { get; set; }
    public string finalCalledPartyNumberPartition { get; set; }
    public string lastRedirectDnPartition { get; set; }
    public string duration { get; set; }
    [Index]
    [MaxLength(64)]
    public string origDeviceName { get; set; }
    [Index]
    [MaxLength(64)]
    public string destDeviceName { get; set; }
    public string origCallTerminationOnBehalfOf { get; set; }
    public string destCallTerminationOnBehalfOf { get; set; }
    public string origCalledPartyRedirectOnBehalfOf { get; set; }
    public string lastRedirectRedirectOnBehalfOf { get; set; }
    public string origCalledPartyRedirectReason { get; set; }
    public string lastRedirectRedirectReason { get; set; }
    public string destConversationId { get; set; }
    public string globalCallId_ClusterID { get; set; }
    public string joinOnBehalfOf { get; set; }
    public string comment { get; set; }
    public string authCodeDescription { get; set; }
    public string authorizationLevel { get; set; }
    public string clientMatterCode { get; set; }
    public string origDTMFMethod { get; set; }
    public string destDTMFMethod { get; set; }
    public string callSecuredStatus { get; set; }
    public string origConversationId { get; set; }
    public string origMediaCap_Bandwidth { get; set; }
    public string destMediaCap_Bandwidth { get; set; }
    public string authorizationCodeValue { get; set; }
    public string outpulsedCallingPartyNumber { get; set; }
    public string outpulsedCalledPartyNumber { get; set; }
    public string origIpv4v6Addr { get; set; }
    public string destIpv4v6Addr { get; set; }
    public string origVideoCap_Codec_Channel2 { get; set; }
    public string origVideoCap_Bandwidth_Channel2 { get; set; }
    public string origVideoCap_Resolution_Channel2 { get; set; }
    public string origVideoTransportAddress_IP_Channel2 { get; set; }
    public string origVideoTransportAddress_Port_Channel2 { get; set; }
    public string origVideoChannel_Role_Channel2 { get; set; }
    public string destVideoCap_Codec_Channel2 { get; set; }
    public string destVideoCap_Bandwidth_Channel2 { get; set; }
    public string destVideoCap_Resolution_Channel2 { get; set; }
    public string destVideoTransportAddress_IP_Channel2 { get; set; }
    public string destVideoTransportAddress_Port_Channel2 { get; set; }
    public string destVideoChannel_Role_Channel2 { get; set; }
    public string IncomingProtocolID { get; set; }
    public string IncomingProtocolCallRef { get; set; }
    public string OutgoingProtocolID { get; set; }
    public string OutgoingProtocolCallRef { get; set; }
    public string currentRoutingReason { get; set; }
    public string origRoutingReason { get; set; }
    public string lastRedirectingRoutingReason { get; set; }
    public string huntPilotPartition { get; set; }
    public string huntPilotDN { get; set; }
    public string calledPartyPatternUsage { get; set; }
    public string IncomingICID { get; set; }
    public string IncomingOrigIOI { get; set; }
    public string IncomingTermIOI { get; set; }
    public string OutgoingICID { get; set; }
    public string OutgoingOrigIOI { get; set; }
    public string OutgoingTermIOI { get; set; }
    public string outpulsedOriginalCalledPartyNumber { get; set; }
    public string outpulsedLastRedirectingNumber { get; set; }
    public string wasCallQueued { get; set; }
    public string totalWaitTimeInQueue { get; set; }
    public string callingPartyNumber_uri { get; set; }
    public string originalCalledPartyNumber_uri { get; set; }
    public string finalCalledPartyNumber_uri { get; set; }
    public string lastRedirectDn_uri { get; set; }
    public string mobileCallingPartyNumber { get; set; }
    public string finalMobileCalledPartyNumber { get; set; }
    public string origMobileDeviceName { get; set; }
    public string destMobileDeviceName { get; set; }
    public string origMobileCallDuration { get; set; }
    public string destMobileCallDuration { get; set; }
    public string mobileCallType { get; set; }
    public string originalCalledPartyPattern { get; set; }
    public string finalCalledPartyPattern { get; set; }
    public string lastRedirectingPartyPattern { get; set; }
    public string huntPilotPattern { get; set; }
}
