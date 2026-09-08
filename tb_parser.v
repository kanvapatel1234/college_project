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

    always #5 clk = ~clk;

    reg [7:0] packet_mem [0:2047];
    integer pkt_len;
    integer i;

    initial begin
        for (i = 0; i < 2048; i = i + 1) packet_mem[i] = 8'hxx;
        $readmemh("packet_data.hex", packet_mem);

        pkt_len = 0;
        while (packet_mem[pkt_len] !== 8'hxx && pkt_len < 2048) begin
            pkt_len = pkt_len + 1;
        end
        clk = 0;
        rst_n = 0;
        s_axis_tvalid = 0;
        s_axis_tlast = 0;
        s_axis_tdata = 8'h00;

        $dumpfile("parser_wave.vcd");
        $dumpvars(0, tb_parser);

        #20 rst_n = 1;
        #10;

        // Stream Scapy bytes into the parser engine
        for (i = 0; i < pkt_len; i = i + 1) begin
            @(posedge clk);
            s_axis_tvalid <= 1'b1;
            s_axis_tdata  <= packet_mem[i];
            s_axis_tlast  <= (i == pkt_len - 1) ? 1'b1 : 1'b0;
        end

        @(posedge clk);
        s_axis_tvalid <= 1'b0;
        s_axis_tlast  <= 1'b0;
        s_axis_tdata  <= 8'h00;

        #50;
        $display("----------------------------------------");
        $display("SCAPY PACKET EXTRACTION RESULTS:");
        $display("Source IP       : %h (Expected: 0a00002d)", src_ip);
        $display("Destination IP  : %h (Expected: ac100163)", dst_ip);
        $display("Source Port     : %d (%h) (Expected: 54321 / d431)", src_port, src_port);
        $display("Destination Port: %d (%h) (Expected: 443 / 01bb)", dst_port, dst_port);
        $display("Payload Valid   : %b (Expected: 1)", payload_valid);
        $display("----------------------------------------");
        $finish;
    end
endmodule