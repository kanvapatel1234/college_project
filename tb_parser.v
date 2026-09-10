`timescale 1ns / 1ps

module tb_parser;

    reg        clk;
    reg        rst_n;
    reg  [7:0] s_axis_tdata;
    reg        s_axis_tvalid;
    reg        s_axis_tlast;

    wire [31:0] src_ip;
    wire [31:0] dst_ip;
    wire [15:0] src_port;
    wire [15:0] dst_port;
    wire        payload_valid;
    wire [7:0]  payload_data_out;
    wire        payload_present;
    wire [15:0] payload_byte_count;

    packet_parser_top uut (
        .clk(clk),
        .rst_n(rst_n),
        .s_axis_tdata(s_axis_tdata),
        .s_axis_tvalid(s_axis_tvalid),
        .s_axis_tlast(s_axis_tlast),
        .parsed_src_ip(src_ip),
        .parsed_dst_ip(dst_ip),
        .parsed_src_port(src_port),
        .parsed_dst_port(dst_port),
        .payload_valid(payload_valid),
        .payload_data_out(payload_data_out),
        .payload_present(payload_present),
        .payload_byte_count(payload_byte_count)
    );

    // 100MHz Clock Generation (10ns period)
    always #5 clk = ~clk;

    // Buffer expanded to 16KB for jumbo/reassembled stream frames
    reg [7:0] packet_mem [0:16383];
    integer pkt_len;
    integer i;

    initial begin
        clk           = 0;
        rst_n         = 0;
        s_axis_tdata  = 8'h00;
        s_axis_tvalid = 0;
        s_axis_tlast  = 0;

        // Initialize with unread markers
        for (i = 0; i < 16384; i = i + 1) packet_mem[i] = 8'hxx;
        $readmemh("packet_data.hex", packet_mem);

        // Count exact packet length up to 16KB
        pkt_len = 0;
        while (packet_mem[pkt_len] !== 8'hxx && pkt_len < 16384) begin
            pkt_len = pkt_len + 1;
        end

        // Hardware Reset Sequence
        #20;
        rst_n = 1;
        #10;

        // Stream raw bytes into the Verilog parser
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

        #20;

        // Simulation text outputs parsed by Python regex
        $display("----------------------------------------");
        $display("Source IP       : %h", src_ip);
        $display("Destination IP  : %h", dst_ip);
        $display("Source Port     : %d", src_port);
        $display("Destination Port: %d", dst_port);
        $display("Payload Present : %d", payload_present);
        $display("Payload Bytes   : %d", payload_byte_count);
        $write("Payload Hex     : ");
        for (i = 0; i < ((payload_byte_count > 32) ? 32 : payload_byte_count); i = i + 1) begin
            $write("%02h", uut.payload_buffer[i]);
        end
        $write("\n");
        $display("----------------------------------------");

        $finish;
    end

endmodule