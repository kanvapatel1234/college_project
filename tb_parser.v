`timescale 1ns / 1ps

module tb_parser();
    reg clk;
    reg rst_n;
    reg [7:0] s_axis_tdata;
    reg s_axis_tvalid;
    reg s_axis_tlast;
    wire s_axis_tready;

    wire [31:0] src_ip, dst_ip;
    wire [15:0] src_port, dst_port;
    wire payload_valid;

    // Unit Under Test (UUT)
    packet_parser_top uut (
        .clk(clk),
        .rst_n(rst_n),
        .s_axis_tdata(s_axis_tdata),
        .s_axis_tvalid(s_axis_tvalid),
        .s_axis_tlast(s_axis_tlast),
        .s_axis_tready(s_axis_tready),
        .parsed_src_ip(src_ip),
        .parsed_dst_ip(dst_ip),
        .parsed_src_port(src_port),
        .parsed_dst_port(dst_port),
        .payload_valid(payload_valid)
    );

    // 100MHz Clock Generation
    always #5 clk = ~clk;

    // Frame storage: 14B Eth + 20B IPv4 + 20B TCP + 7B Payload
    reg [7:0] mock_packet [0:60];
    integer i;

    initial begin
        // Ethernet Header: EtherType = 0x0800 (IPv4)
        mock_packet[12] = 8'h08; mock_packet[13] = 8'h00; 

        // IPv4 Header:
        // Src IP: 192.168.2.10 -> 0xC0, 0xA8, 0x02, 0x0A
        mock_packet[14+12] = 8'hC0; mock_packet[14+13] = 8'hA8; 
        mock_packet[14+14] = 8'h02; mock_packet[14+15] = 8'h0A;

        // Dst IP: 192.168.2.1  -> 0xC0, 0xA8, 0x02, 0x01
        mock_packet[14+16] = 8'hC0; mock_packet[14+17] = 8'hA8; 
        mock_packet[14+18] = 8'h02; mock_packet[14+19] = 8'h01;

        // TCP Header:
        // Src Port: 12345 -> 0x3039
        mock_packet[34+0] = 8'h30; mock_packet[34+1] = 8'h39;
        // Dst Port: 80    -> 0x0050
        mock_packet[34+2] = 8'h00; mock_packet[34+3] = 8'h50;

        // Payload: "MALWARE"
        mock_packet[54] = "M"; mock_packet[55] = "A";
        mock_packet[56] = "L"; mock_packet[57] = "W";
        mock_packet[58] = "A"; mock_packet[59] = "R";
        mock_packet[60] = "E";

        // Initial Signal States
        clk = 0;
        rst_n = 0;
        s_axis_tvalid = 0;
        s_axis_tlast = 0;
        s_axis_tdata = 8'h00;

        // VCD waveform dump
        $dumpfile("parser_wave.vcd");
        $dumpvars(0, tb_parser);

        // Hold reset for 20ns
        #20 rst_n = 1;
        #10;

        // Stream the packet byte-by-byte into the parser
        for (i = 0; i < 61; i = i + 1) begin
            @(posedge clk);
            s_axis_tvalid <= 1'b1;
            s_axis_tdata  <= mock_packet[i];
            s_axis_tlast  <= (i == 60) ? 1'b1 : 1'b0;
        end

        // Deassert AXI Stream
        @(posedge clk);
        s_axis_tvalid <= 1'b0;
        s_axis_tlast  <= 1'b0;
        s_axis_tdata  <= 8'h00;

        #50;
        $display("----------------------------------------");
        $display("PARSER EXTRACTION RESULTS:");
        $display("Source IP      : %h (Expected: c0a8020a)", src_ip);
        $display("Destination IP : %h (Expected: c0a80201)", dst_ip);
        $display("Source Port    : %d (Expected: 12345 / 0x3039)", src_port);
        $display("Destination Port: %d (Expected: 80 / 0x0050)", dst_port);
        $display("Payload Valid  : %b", payload_valid);
        $display("----------------------------------------");
        $finish;
    end
endmodule