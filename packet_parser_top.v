`timescale 1ns / 1ps

module packet_parser_top (
    input  wire        clk,
    input  wire        rst_n,

    // AXI4-Stream Input Interface
    input  wire [7:0]  s_axis_tdata,
    input  wire        s_axis_tvalid,
    input  wire        s_axis_tlast,
    output wire        s_axis_tready,

    // Parsed Field Registers
    output reg [31:0]  parsed_src_ip,
    output reg [31:0]  parsed_dst_ip,
    output reg [15:0]  parsed_src_port,
    output reg [15:0]  parsed_dst_port,
    output reg         payload_valid
);

    // Accept incoming bytes on every clock cycle
    assign s_axis_tready = 1'b1;

    // FSM States
    localparam STATE_ETH     = 3'd0;
    localparam STATE_IPV4    = 3'd1;
    localparam STATE_TCP     = 3'd2;
    localparam STATE_PAYLOAD = 3'd3;

    reg [2:0] state;
    reg [7:0] byte_cnt;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state           <= STATE_ETH;
            byte_cnt        <= 8'd0;
            parsed_src_ip   <= 32'd0;
            parsed_dst_ip   <= 32'd0;
            parsed_src_port <= 16'd0;
            parsed_dst_port <= 16'd0;
            payload_valid   <= 1'b0;
        end else if (s_axis_tvalid) begin
            // Reset state machine on packet termination
            if (s_axis_tlast) begin
                state         <= STATE_ETH;
                byte_cnt      <= 8'd0;
                payload_valid <= 1'b0;
            end else begin
                case (state)
                    // Ethernet Header (14 bytes)
                    STATE_ETH: begin
                        if (byte_cnt == 8'd13) begin
                            state    <= STATE_IPV4;
                            byte_cnt <= 8'd0;
                        end else begin
                            byte_cnt <= byte_cnt + 1'b1;
                        end
                    end

                    // IPv4 Header (20 bytes standard)
                    STATE_IPV4: begin
                        case (byte_cnt)
                            8'd12, 8'd13, 8'd14, 8'd15: parsed_src_ip <= {parsed_src_ip[23:0], s_axis_tdata};
                            8'd16, 8'd17, 8'd18, 8'd19: parsed_dst_ip <= {parsed_dst_ip[23:0], s_axis_tdata};
                        endcase

                        if (byte_cnt == 8'd19) begin
                            state    <= STATE_TCP;
                            byte_cnt <= 8'd0;
                        end else begin
                            byte_cnt <= byte_cnt + 1'b1;
                        end
                    end

                    // TCP Header (20 bytes standard)
                    STATE_TCP: begin
                        case (byte_cnt)
                            8'd0, 8'd1: parsed_src_port <= {parsed_src_port[7:0], s_axis_tdata};
                            8'd2, 8'd3: parsed_dst_port <= {parsed_dst_port[7:0], s_axis_tdata};
                        endcase

                        if (byte_cnt == 8'd19) begin
                            state         <= STATE_PAYLOAD;
                            payload_valid <= 1'b1;
                        end else begin
                            byte_cnt <= byte_cnt + 1'b1;
                        end
                    end

                    // Payload Region (Streaming to DPI engine)
                    STATE_PAYLOAD: begin
                        payload_valid <= 1'b1;
                    end

                    default: state <= STATE_ETH;
                endcase
            end
        end
    end

endmodule