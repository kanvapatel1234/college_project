`timescale 1ns / 1ps

module packet_parser_top (
    input  wire        clk,
    input  wire        rst_n,
    
    // AXI-Stream Slave Interface
    input  wire [7:0]  s_axis_tdata,
    input  wire        s_axis_tvalid,
    input  wire        s_axis_tlast,
    
    // Parsed Headers
    output reg  [31:0] parsed_src_ip,
    output reg  [31:0] parsed_dst_ip,
    output reg  [15:0] parsed_src_port,
    output reg  [15:0] parsed_dst_port,
    
    // Real-Time Payload Signals
    output reg         payload_valid,     // High ONLY when current byte is payload
    output reg  [7:0]  payload_data_out,  // Real-time payload byte stream
    
    // Latched Payload Metadata & Captured Buffer
    output reg         payload_present,   // Stays 1 if packet contained any payload
    output reg  [15:0] payload_byte_count // Total payload byte count
);

    reg [15:0] byte_cnt;
    reg [7:0]  ip_protocol;
    reg [5:0]  ip_header_len;       // Bytes (IHL * 4)
    reg [6:0]  tcp_header_len;      // Bytes (Data Offset * 4)
    reg [15:0] payload_start_offset;

    // Internal payload capture buffer (Stores up to 64 bytes)
    reg [7:0] payload_buffer [0:63];

    // Payload start calculation
    always @(*) begin
        if (ip_protocol == 8'h06) begin
            // Ethernet(14) + IP Header Length + TCP Header Length
            payload_start_offset = 16'd14 + ip_header_len + tcp_header_len;
        end else if (ip_protocol == 8'h11) begin
            // Ethernet(14) + IP Header Length + UDP Header(8)
            payload_start_offset = 16'd14 + ip_header_len + 16'd8;
        end else begin
            payload_start_offset = 16'd54;
        end
    end

    integer k;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            byte_cnt           <= 16'd0;
            parsed_src_ip      <= 32'd0;
            parsed_dst_ip      <= 32'd0;
            parsed_src_port    <= 16'd0;
            parsed_dst_port    <= 16'd0;
            ip_protocol        <= 8'd0;
            ip_header_len      <= 6'd20; // Default 20 bytes
            tcp_header_len     <= 7'd20; // Default 20 bytes
            payload_valid      <= 1'b0;
            payload_data_out   <= 8'd0;
            payload_present    <= 1'b0;
            payload_byte_count <= 16'd0;
            for (k = 0; k < 64; k = k + 1) payload_buffer[k] <= 8'h00;
        end else if (s_axis_tvalid) begin

            // --- 1. IP Header Extraction ---
            case (byte_cnt)
                16'd14: ip_header_len <= {s_axis_tdata[3:0], 2'b00}; // IHL * 4
                16'd23: ip_protocol   <= s_axis_tdata;              // 0x06=TCP, 0x11=UDP
                16'd26: parsed_src_ip[31:24] <= s_axis_tdata;
                16'd27: parsed_src_ip[23:16] <= s_axis_tdata;
                16'd28: parsed_src_ip[15:8]  <= s_axis_tdata;
                16'd29: parsed_src_ip[7:0]   <= s_axis_tdata;
                16'd30: parsed_dst_ip[31:24] <= s_axis_tdata;
                16'd31: parsed_dst_ip[23:16] <= s_axis_tdata;
                16'd32: parsed_dst_ip[15:8]  <= s_axis_tdata;
                16'd33: parsed_dst_ip[7:0]   <= s_axis_tdata;
            endcase

            // --- 2. TCP/UDP Ports Extraction ---
            // Byte 34 is start of TCP/UDP if IP options are absent
            if (byte_cnt == (16'd14 + ip_header_len)) begin
                parsed_src_port[15:8] <= s_axis_tdata;
            end else if (byte_cnt == (16'd14 + ip_header_len + 16'd1)) begin
                parsed_src_port[7:0]  <= s_axis_tdata;
            end else if (byte_cnt == (16'd14 + ip_header_len + 16'd2)) begin
                parsed_dst_port[15:8] <= s_axis_tdata;
            end else if (byte_cnt == (16'd14 + ip_header_len + 16'd3)) begin
                parsed_dst_port[7:0]  <= s_axis_tdata;
            end

            // TCP Data Offset (Header length in 32-bit words) at relative offset 12
            if (ip_protocol == 8'h06 && byte_cnt == (16'd14 + ip_header_len + 16'd12)) begin
                tcp_header_len <= {s_axis_tdata[7:4], 2'b00};
            end

            // --- 3. Payload Extraction & Buffering ---
            if (byte_cnt >= payload_start_offset) begin
                payload_valid    <= 1'b1;
                payload_data_out <= s_axis_tdata;
                payload_present  <= 1'b1;
                
                // Store first 64 bytes into hardware capture buffer
                if (payload_byte_count < 16'd64) begin
                    payload_buffer[payload_byte_count[5:0]] <= s_axis_tdata;
                end
                payload_byte_count <= payload_byte_count + 1'b1;
            end else begin
                payload_valid <= 1'b0;
            end

            // End of frame handling
            if (s_axis_tlast) begin
                byte_cnt <= 16'd0;
            end else begin
                byte_cnt <= byte_cnt + 1'b1;
            end
        end else begin
            payload_valid <= 1'b0;
        end
    end

endmodule