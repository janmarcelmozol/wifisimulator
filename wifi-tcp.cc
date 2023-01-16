/*
Simulação Redes Projeto Dongwon.

Jan Marcel Massoni Mozol:

*/

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cstdlib>

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/global-route-manager.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/assert.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "ns3/wifi-module.h"
#include "ns3/flow-monitor.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/flow-monitor-module.h" 
#include "ns3/propagation-module.h"


#include "ns3/stats-module.h"

NS_LOG_COMPONENT_DEFINE ("wifi-tcp");

using namespace ns3;
using namespace std;

Ptr<PacketSink> sink;                         /* Ponteiro para aplicacao receptora de pacotes */
uint64_t lastTotalRx = 0;                     /* Valor do ultimo total de bytes recebidos */



// Funcao que faz o calculo das caracteristicas dos flows
void 
print_stats (FlowMonitor::FlowStats st) 
{ 
     std::cout << "  Tx Bytes: " << st.txBytes << std::endl; 
     std::cout << "  Rx Bytes: " << st.rxBytes << std::endl; 
     std::cout << "  Tx Packets: " << st.txPackets << std::endl; 
     std::cout << "  Rx Packets: " << st.rxPackets << std::endl; 
     std::cout << "  Lost Packets: " << st.lostPackets << std::endl; 

     if (st.rxPackets > 0) 
     { 
     	std::cout << "  Mean{Delay}: " << (st.delaySum.GetSeconds() / st.rxPackets); 
        std::cout << "  Mean{Jitter}: " << (st.jitterSum.GetSeconds() / (st.rxPackets-1)); 
        std::cout << "  Mean{Hop Count}: " << st.timesForwarded / st.rxPackets + 1 << std::endl;
     } 

     if (false) 
     { 
     	std::cout << "Delay Histogram" << std::endl; 
        for (uint32_t i=0; i<st.delayHistogram.GetNBins (); i++) 
			std::cout << " " << i << "(" << st.delayHistogram.GetBinStart (i) << "-" << st.delayHistogram.GetBinEnd (i) << "): " << st.delayHistogram.GetBinCount (i) << std::endl; 
       	
		std::cout << "Jitter Histogram" << std::endl; 
        for (uint32_t i=0; i<st.jitterHistogram.GetNBins (); i++ ) 
        	std::cout << " " << i << "(" << st.jitterHistogram.GetBinStart (i) << "-" << st.jitterHistogram.GetBinEnd (i) << "): " << st.jitterHistogram.GetBinCount (i) << std::endl; 

        std::cout << "PacketSize Histogram  "<< std::endl; 
        for (uint32_t i=0; i<st.packetSizeHistogram.GetNBins (); i++ ) 
        	std::cout << " " << i << "(" << st.packetSizeHistogram.GetBinStart (i) << "-" << st.packetSizeHistogram.GetBinEnd (i) << "): " << st.packetSizeHistogram.GetBinCount (i) << std::endl; 
     } 

     for (uint32_t i=0; i<st.packetsDropped.size (); i++) 
     	std::cout << "  Packets dropped by reason " << i << ": " << st.packetsDropped [i] << std::endl; 
     for (uint32_t i=0; i<st.bytesDropped.size(); i++) 
        std::cout << "Bytes dropped by reason " << i << ": " << st.bytesDropped[i] << std::endl; 
} 



// inicio do programa
int
main(int argc, char *argv[])
{
  uint32_t payloadSize = 512;                       /* Carga util de 512 bytes para trafego CBR. */
  uint32_t payloadBurst = 1500;                     /* Carga util de 1500 bytes para trafego rajada */
  double simulationTime = 30;                         /* Simulation time in seconds. */
  bool pcapTracing = false;                          /* PCAP Tracing habilitado ou nao */
  int nWifi = 0;                                      /* Numero de Dispositivos Wifi */
  srand ( (unsigned)time ( NULL ) ); 
  string Results("no"); 
  bool Plot = false;
  std::string tr_name ("wifi-throughput.tr");
  std::string pcap_name ("wifi-throughput-pcap");
  std::string flow_name ("wifi-throughput.xml");
  std::string anim_name ("wifi-throughput.anim.xml");
  std::string AppPacketRateBurst ("512kbps"); //Burst
  std::string AppPacketRate ("2048kbps"); //CBR


  double SinkStartTime  = 8.0;
  double SinkStopTime   = 16.0;
  double AppStartTime   = 10.0;
  double AppStopTime    = 15.0;


  /* Command line argument parser setup. */
  CommandLine cmd;
  cmd.AddValue ("payloadSize", "Payload size in bytes", payloadSize);
  cmd.AddValue ("simulationTime", "Simulation time in seconds", simulationTime);
  cmd.AddValue ("pcap", "Enable/disable PCAP Tracing", pcapTracing);
  cmd.AddValue ("nWifi", "Add n wifi devices to the toplogy", nWifi);
  cmd.Parse (argc, argv);

  /* No fragmentation and no RTS/CTS */
  Config::SetDefault ("ns3::WifiRemoteStationManager::FragmentationThreshold", StringValue ("999999"));
  Config::SetDefault ("ns3::WifiRemoteStationManager::RtsCtsThreshold", StringValue ("999999"));

  /* Configure TCP Options */
  Config::SetDefault ("ns3::TcpSocket::SegmentSize", UintegerValue (payloadSize));


   /* Create fixed Nodes stations A and B and AP*/
  NodeContainer networkNodes;
  networkNodes.Create (3);
  Ptr<Node> apWifiNode = networkNodes.Get (0);
  Ptr<Node> staWifiNode = networkNodes.Get (1);
  Ptr<Node> stbWifiNode = networkNodes.Get (2);

  /* Setup Physical Layer */
  WifiHelper wifiHelper;
  wifiHelper.SetStandard(WIFI_PHY_STANDARD_80211g);  
  wifiHelper.SetRemoteStationManager ("ns3::ConstantRateWifiManager","DataMode",StringValue ("ErpOfdmRate54Mbps"), "ControlMode",StringValue ("ErpOfdmRate54Mbps"));

  /* Set up Legacy Channel */
  YansWifiChannelHelper wifiChannel;
  wifiChannel.SetPropagationDelay ("ns3::ConstantSpeedPropagationDelayModel");
  wifiChannel.AddPropagationLoss ("ns3::LogDistancePropagationLossModel", "Exponent", DoubleValue (3.0), "ReferenceLoss", DoubleValue (40.0459));
  YansWifiPhyHelper wifiPhy = YansWifiPhyHelper::Default ();
  wifiPhy.SetChannel (wifiChannel.Create ());

  /* Configure AP network settings */
  WifiMacHelper wifiMac;
  Ssid ssid = Ssid ("network");
  wifiMac.SetType ("ns3::ApWifiMac","Ssid", SsidValue (ssid));

  NetDeviceContainer apDevice;
  apDevice = wifiHelper.Install (wifiPhy, wifiMac, apWifiNode);

  /* Configure Wifi network on stations A and B*/
  wifiMac.SetType ("ns3::StaWifiMac","Ssid", SsidValue (ssid));

  NetDeviceContainer staDevices;
  NetDeviceContainer stbDevices;
  staDevices = wifiHelper.Install (wifiPhy, wifiMac, staWifiNode);
  stbDevices = wifiHelper.Install (wifiPhy, wifiMac, stbWifiNode);
  

  /* Mobility model - static AP */
  MobilityHelper mobility;
  Ptr<ListPositionAllocator> positionAlloc = CreateObject<ListPositionAllocator> ();
  positionAlloc->Add (Vector (1.0, 1.0, 1.0)); //AP
  //positionAlloc->Add (Vector (1.0, 1.0, 0.0)); //STA
  //positionAlloc->Add (Vector (30.0, 30.0, 30.0)); //STB
  mobility.SetPositionAllocator (positionAlloc);
  mobility.SetMobilityModel ("ns3::ConstantPositionMobilityModel");
  mobility.Install (apWifiNode);

/* Mobility model - mobile STA and STB */
  mobility.SetPositionAllocator ("ns3::GridPositionAllocator","MinX", DoubleValue (0.0),"MinY", DoubleValue (0.0),"DeltaX", DoubleValue (2.5),"DeltaY", DoubleValue (2.5),"GridWidth", UintegerValue (3),"LayoutType", StringValue ("RowFirst"));
  mobility.SetMobilityModel ("ns3::RandomWalk2dMobilityModel","Bounds", RectangleValue (Rectangle (-50, 50, -50, 50)));
  mobility.Install (staWifiNode);
  mobility.Install (stbWifiNode);

  /* Internet stack */
  InternetStackHelper stack;
  stack.Install (networkNodes); //ap, sta and stb only

  Ipv4AddressHelper address;
  address.SetBase ("10.0.0.0", "255.255.255.0");

  Ipv4InterfaceContainer apInterface;
  apInterface = address.Assign (apDevice);

  Ipv4InterfaceContainer staInterface;
  staInterface = address.Assign (staDevices);

  Ipv4InterfaceContainer stbInterface;
  stbInterface = address.Assign (stbDevices);


  /* Populate routing table */
  Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

  uint16_t port = 9;
  //uint32_t maxBytes = 0;
  /* Install Bulksender TCP Application on STA node - Source close to AP - Experiment 1 only*/
  //BulkSendHelper sourceA ("ns3::TcpSocketFactory",InetSocketAddress (apInterface.GetAddress (0), port)); //Connect to AP node
  //sourceA.SetAttribute ("MaxBytes", UintegerValue (maxBytes)); // Set the amount of data to send in bytes.  Zero is unlimited.
  //ApplicationContainer sourceAppsA = sourceA.Install (networkNodes.Get (1));
  
  /* Install Bulksender TCP Application on STB node - Source far to AP */
  //BulkSendHelper sourceB ("ns3::TcpSocketFactory",InetSocketAddress (apInterface.GetAddress (0), port)); //Connect to AP node
  //sourceB.SetAttribute ("MaxBytes", UintegerValue (maxBytes)); // Set the amount of data to send in bytes.  Zero is unlimited.
  //ApplicationContainer sourceAppsB = sourceB.Install (networkNodes.Get (2));

  // Create a PacketSink Application and install it on node AP - node 0
  PacketSinkHelper sink ("ns3::TcpSocketFactory",InetSocketAddress (Ipv4Address::GetAny (), port));
  ApplicationContainer sinkApps = sink.Install (networkNodes.Get (0));


  /* Install TCP/UDP Transmitter on the station A - close */ 
  OnOffHelper sourceA ("ns3::TcpSocketFactory", (InetSocketAddress (apInterface.GetAddress (0), port))); //connect to AP
  sourceA.SetAttribute ("PacketSize", UintegerValue (payloadSize));
  sourceA.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
  sourceA.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
  sourceA.SetAttribute ("DataRate", DataRateValue (DataRate (AppPacketRate)));
  ApplicationContainer sourceAppsA = sourceA.Install (networkNodes.Get(1));
  
  // Install TCP/UDP Transmitter on the station B - far 
  OnOffHelper sourceB ("ns3::TcpSocketFactory", (InetSocketAddress (apInterface.GetAddress (0), 9))); //connect to AP
  sourceB.SetAttribute ("PacketSize", UintegerValue (payloadSize));
  sourceB.SetAttribute ("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
  sourceB.SetAttribute ("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
  sourceB.SetAttribute ("DataRate", DataRateValue (DataRate (AppPacketRate)));
  ApplicationContainer sourceAppsB = sourceB.Install (networkNodes.Get(2));
 

 // If nWifi >0 then we need to create more Wifi devices and join them to the network
 if (nWifi != 0) 
 { 
    //Create the Wifi nodes
    NodeContainer nodes;
  	nodes.Create(nWifi);

  	/* Configure other Wifi devices joining the network */
  	NetDeviceContainer nodeDevices = wifiHelper.Install (wifiPhy, wifiMac, nodes); 

    /* Mobility model - Random for other wifi node devices*/
  	mobility.SetPositionAllocator ("ns3::GridPositionAllocator","MinX", DoubleValue (0.0),"MinY", DoubleValue (0.0),"DeltaX", DoubleValue (5.0),"DeltaY", DoubleValue (10.0),"GridWidth", UintegerValue (3),"LayoutType", StringValue ("RowFirst"));
  	mobility.SetMobilityModel ("ns3::RandomWalk2dMobilityModel","Bounds", RectangleValue (Rectangle (-50, 50, -50, 50)));
  	mobility.Install (nodes);

    //Install the network stack
  	stack.Install (nodes); //other wifi devices
  	Ipv4InterfaceContainer nodesInterfaces;
  	nodesInterfaces = address.Assign (nodeDevices);

    // ---------- Create n*(n-1) CBR Flows -------------------------------------
	NS_LOG_INFO ("Setup Packet Sinks.");
	for (int i = 0; i < nWifi; i++)
    {
        PacketSinkHelper sink ("ns3::UdpSocketFactory", InetSocketAddress (Ipv4Address::GetAny (), port));
    	ApplicationContainer apps_sink = sink.Install (nodes.Get (i));   // sink is installed on all nodes
    	apps_sink.Start (Seconds (SinkStartTime));
       	apps_sink.Stop (Seconds (SinkStopTime));
    }
    NS_LOG_INFO ("Setup CBR Traffic Sources.");
	for (int i = 0; i < nWifi; i++)
    {
        for (int j = 0; j < nWifi; j++)
        {
            if (i != j)
            {
                // We needed to generate a random number (rn) to be used to eliminate
                // the artificial congestion caused by sending the packets at the
                // same time. This rn is added to AppStartTime to have the sources
                // start at different time, however they will still send at the same rate.
                Ptr<UniformRandomVariable> x = CreateObject<UniformRandomVariable> ();
                x->SetAttribute ("Min", DoubleValue (0));
                x->SetAttribute ("Max", DoubleValue (1));
                double rn = x->GetValue ();
                Ptr<Node> n = nodes.Get (j);
                Ptr<Ipv4> ipv4 = n->GetObject<Ipv4> ();
                Ipv4InterfaceAddress ipv4_int_addr = ipv4->GetAddress (1, 0);
                Ipv4Address ip_addr = ipv4_int_addr.GetLocal ();
                OnOffHelper onoff ("ns3::UdpSocketFactory", InetSocketAddress (ip_addr, port)); // traffic flows from node[i] to node[j]
                onoff.SetAttribute("DataRate", DataRateValue (DataRate (AppPacketRateBurst)));
                onoff.SetAttribute("PacketSize", UintegerValue (payloadBurst));
                onoff.SetAttribute("OnTime", StringValue ("ns3::ConstantRandomVariable[Constant=1]"));
                onoff.SetAttribute("OffTime", StringValue ("ns3::ConstantRandomVariable[Constant=0]"));
                ApplicationContainer apps = onoff.Install (nodes.Get (i));  // traffic sources are installed on all nodes
                apps.Start (Seconds (AppStartTime + rn));
                apps.Stop (Seconds (AppStopTime));
            }
        }
    }
  
    // ---------- End of Create n*(n-1) CBR Flows ------------------------------
 }
 
 /* Start Applications */

 /* Enable Traces 
 if (pcapTracing)
   {
     wifiPhy.SetPcapDataLinkType (YansWifiPhyHelper::DLT_IEEE802_11_RADIO);
     wifiPhy.EnablePcap ("AccessPoint", apDevice);
     wifiPhy.EnablePcap ("StationA", staDevices);
     wifiPhy.EnablePcap ("StationB", stbDevices);
   } */

 /* Start flow monitoring */
 Ptr<FlowMonitor> flowmon;
 FlowMonitorHelper flowmonHelper;
 flowmon = flowmonHelper.InstallAll();
 flowmon->SetAttribute("DelayBinWidth", DoubleValue(0.001));
 flowmon->SetAttribute("JitterBinWidth", DoubleValue(0.001));
 flowmon->SetAttribute("PacketSizeBinWidth", DoubleValue(20));

 //Netanim XML
 AnimationInterface anim (anim_name.c_str ());
 

  sinkApps.Start (Seconds (0.0));
  sinkApps.Stop (Seconds (20.0));
  Ptr<UniformRandomVariable> y = CreateObject<UniformRandomVariable> ();
  y->SetAttribute ("Min", DoubleValue (0));
  y->SetAttribute ("Max", DoubleValue (1));
  double rnd = y->GetValue ();
  sourceAppsB.Start (Seconds (1 + rnd));
  sourceAppsB.Stop (Seconds (19.0));
  sourceAppsA.Start (Seconds (1.1 + rnd));
  sourceAppsA.Stop (Seconds (19.1));

 /* Start Simulation */
 Simulator::Stop (Seconds (simulationTime));
 Simulator::Run ();
 
 flowmon->CheckForLostPackets(); 
 Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowmonHelper.GetClassifier()); 
 //Ptr<FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>flowmonHelper.GetClassifier(); 
 // Print per flow statistics
 FlowMonitor::FlowStatsContainer stats = flowmon->GetFlowStats ();
 uint32_t txPacketsum = 0;
 uint32_t rxPacketsum = 0;
 uint32_t DropPacketsum = 0;
 uint32_t LostPacketsum = 0;
 double Delaysum = 0;
 double Throughputsum = 0;
 double avgDelay = 0;


 if(Results == "")
 {
    string proto; 
	std::map<FlowId, FlowMonitor::FlowStats> stats = flowmon->GetFlowStats(); 
    for (std::map<FlowId, FlowMonitor::FlowStats>::iterator flow=stats.begin(); flow!=stats.end(); flow++) 
    {
		Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(flow->first); 
        switch(t.protocol)
		{
	        case(6): 
            	proto = "TCP"; 
           		break; 
         	case(17): 
                proto = "UDP"; 
                break; 
         	default: 
                exit(1); 
        } 
        std::cout << "FlowID: " << flow->first << "(" << proto << " " << t.sourceAddress << "/" << t.sourcePort << " --> " << t.destinationAddress << "/" << t.destinationPort << ")" << std::endl; 
        print_stats(flow->second); 
     } 
  } else  
  		flowmon->SerializeToXmlFile(flow_name.c_str(), true, true);
 
 for (std::map<FlowId, FlowMonitor::FlowStats>::const_iterator i = stats.begin (); i != stats.end (); ++i)
 {
    //Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow (i->first);
    /* std::cout << "Flow " << i->first - 2 << " (" << t.sourceAddress << " -> " << t.destinationAddress << ")\n";
    std::cout << "  Tx Packets: " << i->second.txPackets << "\n";
    std::cout << "  Tx Bytes:   " << i->second.txBytes << "\n";
    std::cout << "  TxOffered:  " << i->second.txBytes * 8.0 / 9.0 / 1000 / 1000  << " Mbps\n";
    std::cout << "  Rx Packets: " << i->second.rxPackets << "\n";
    std::cout << "  Rx Bytes:   " << i->second.rxBytes << "\n";
    std::cout << "  Throughput: " << i->second.rxBytes * 8.0 / 9.0 / 1000 / 1000  << " Mbps\n";
    */
    txPacketsum += i->second.txPackets;
    rxPacketsum += i->second.rxPackets;
    LostPacketsum += i->second.lostPackets;
    DropPacketsum += i->second.packetsDropped.size();
    Delaysum += i->second.delaySum.GetSeconds();
    Throughputsum += i->second.rxBytes * 8.0 / 9.0 / 1000 / 1000;
 }
 std::cout << "\n";
 std::cout << "  All Tx Packets: " << txPacketsum << "\n";
 std::cout << "  All Rx Packets: " << rxPacketsum << "\n";
 std::cout << "  All Delay: " << Delaysum / txPacketsum << "\n";
 std::cout << "  All Lost Packets: " << LostPacketsum << "\n";
 std::cout << "  All Drop Packets: " << DropPacketsum << "\n";
 std::cout << "  Packets Delivery Ratio: " << ((rxPacketsum *  100) / txPacketsum) << "%" << "\n";
 std::cout << "  Packets Lost Ratio: " << ((LostPacketsum * 100) / txPacketsum) << "%" << "\n";
 std::cout << "  Throughput total: "<< Throughputsum << "\n";
// std::cout << "  Avg Throughput: "<< averageThroughput << "\n";
  
  if(Plot)
  { 
  	Gnuplot gnuplot("DELAYSbynWifi.png"); 
    Gnuplot2dDataset delaydataset("Delay versus numero de dispositivos wifi"); 
    delaydataset.SetStyle(Gnuplot2dDataset::HISTEPS); 
 	std::map< FlowId, FlowMonitor::FlowStats > stats = flowmon->GetFlowStats(); 
    //for (std::map< FlowId, FlowMonitor::FlowStats >::iterator flow=stats.begin(); flow!=stats.end(); flow++) 
   // {
	//	Ipv4FlowClassifier::FiveTuple tupl = classifier->FindFlow(flow->first); 
      //  if(tupl.protocol == 17 && tupl.sourcePort == 698) 
      //  	continue; 
        delaydataset.Add(
            (int)nWifi, (double)avgDelay
            //(double)flow->second.delaySum.GetSeconds() / (double)flow->second.rxPackets, 
            //(double)flow->second.lostPackets / (((double)flow->second.rxPackets + (double)flow->second.lostPackets)),
           // (double)flow->second.jitterSum.GetSeconds() / (flow->second.rxPackets-1)
        ); 
   // } 
    gnuplot.AddDataset(delaydataset); 
    gnuplot.GenerateOutput(std::cout); 
  } 

  Simulator::Destroy ();
  
  //double averageThroughput = ((sink.GetTotalRx() * 8) / (1e6  * simulationTime));

  /* if (averageThroughput < 50)
    {
      NS_LOG_ERROR ("Obtained throughput is not in the expected boundaries!");
      exit (1);
    } */
  //std::cout << "\n" << averageThroughput << " Mbit/s" << std::endl;
  return 0;
}
