# -*- coding: utf-8 -*-
"""
스마트네트워크서비스 - SDN 실습용 Ryu 컨트롤러 (학생용 버전)

목표:
- 기본 learning switch 기능 구현
- 특정 IP 쌍에 대한 트래픽을 차단하는 간단한 firewall 정책 구현

※ 본 파일은 스켈레톤 코드입니다.
TODO 부분을 직접 작성하지 않으면 firewall 기능이 동작하지 않습니다.
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.lib.packet import ether_types


class SimpleFirewallStudent(app_manager.RyuApp):

    # OpenFlow 1.3 사용
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleFirewallStudent, self).__init__(*args, **kwargs)
        # dpid(스위치 ID)별 MAC 학습 테이블
        # 예: self.mac_to_port[dpid][mac] = port_no
        self.mac_to_port = {}

        # TODO: 차단할 IP 쌍을 정의할 것
        self.block_pairs = set()

        # 10.0.0.1 <-> 10.0.0.3 차단
        self.block_pairs = {
            ("10.0.0.1", "10.0.0.3"),
            ("10.0.0.3", "10.0.0.1")
        }


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        """ 스위치에 flow entry 추가하는 헬퍼 함수 """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    buffer_id=buffer_id,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority,
                                    match=match,
                                    instructions=inst)

        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        스위치가 컨트롤러에 처음 연결될 때 호출됨.
        - table-miss 엔트리 설정 (알 수 없는 패킷은 컨트롤러로 보냄)
        """

        dp = ev.msg.datapath
        op = dp.ofproto
        parser = dp.ofproto_parser

        # TODO: 아래 table-miss 엔트리
        match_all = parser.OFPMatch()
        action_send_controller = [
            parser.OFPActionOutput(op.OFPP_CONTROLLER,
                                   op.OFPCML_NO_BUFFER)
        ]
        self.add_flow(dp, priority=0,
                         match=match_all,
                         actions=action_send_controller)
        

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        스위치에서 컨트롤러로 올라온 Packet-In 이벤트 처리 함수
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        # ==========================
        # 1) MAC 학습 (Learning Switch)
        # ==========================
        # TODO: learning switch의 핵심 코드 한 줄을 작성하시오.
        #  - 의미: 해당 dpid에서 src MAC은 in_port를 통해 들어왔다고 학습
        #
        # 한 줄을 직접 작성
        # -------------------------------
        self.mac_to_port[dpid][src] = in_port
        # -------------------------------

        # ==========================
        # 2) IPv4 헤더 파싱
        # ==========================
        ip4 = pkt.get_protocol(ipv4.ipv4)
        src_ip = None
        dst_ip = None

        # TODO: IPv4 패킷인 경우, src_ip와 dst_ip를 추출하는 코드를 작성하시오
        # 힌트: ip4.src, ip4.dst
        # -------------------------------
        if ip4:
            src_ip = ip4.src
            dst_ip = ip4.dst
        # -------------------------------

        # 디버깅용
        self.logger.info(
            "dpid=%s in_port=%s src=%s dst=%s src_ip=%s dst_ip=%s",
            dpid, in_port, src, dst, src_ip, dst_ip
        )

        # ==========================
        # 3) Firewall 정책 적용
        # ==========================
        # TODO: block_pairs에 포함된 (src_ip, dst_ip) 조합이면
        #       해당 트래픽을 DROP하는 flow entry를 설치하시오.
        #
        # -------------------------------
        # Firewall 정책 적용 구간
        if src_ip and dst_ip and (src_ip, dst_ip) in self.block_pairs:
            self.logger.info("차단 규칙 적용: %s -> %s", src_ip, dst_ip)

            # 해당 IP 조합에 대해 DROP 룰 설치
            drop_match = parser.OFPMatch(
            eth_type=ether_types.ETH_TYPE_IP,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip
            )
            drop_actions = []   # DROP 은 action 없음으로 처리

            # 스위치가 버퍼링한 패킷이 있으면 해당 buffer 사용
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 20, drop_match, drop_actions,
                         buffer_id=msg.buffer_id)
                return

            # buffer 없는 경우 일반 FlowMod
            self.add_flow(datapath, 20, drop_match, drop_actions)
            return         
        # -------------------------------

        # ==========================
        # 4) 기본 포워딩 (학습 스위치 동작)
        # ==========================
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Flow 설치 (성능 향상을 위해)
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            match = parser.OFPMatch(in_port=in_port,
                                    eth_src=src, eth_dst=dst)
            self.add_flow(datapath, priority=10,
                          match=match, actions=actions,
                          buffer_id=msg.buffer_id)
            return
        else:
            match = parser.OFPMatch(in_port=in_port,
                                    eth_src=src, eth_dst=dst)
            self.add_flow(datapath, priority=10,
                          match=match, actions=actions)

        # 실제 패킷 전송
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)
