package Server;

import Utils.AESCBC;
import Utils.RSAUtil;
import Utils.VerifySignature;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class ServerNetty {

    public static void main(String[] args) throws Exception {
        new ServerNetty().start(2929);
    }

    public void start(int port) throws Exception {
        EventLoopGroup boss = new NioEventLoopGroup();
        EventLoopGroup worker = new NioEventLoopGroup();

        try {
            ServerBootstrap server = new ServerBootstrap();
            server.group(boss, worker)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<>() {
                        @Override
                        protected void initChannel(Channel ch) { //Nhận: Network → LineBasedFrameDecoder → StringDecoder → ServerHandler
                            ch.pipeline().addLast(new LineBasedFrameDecoder(8192));
                            ch.pipeline().addLast(new StringDecoder(StandardCharsets.UTF_8));
                            ch.pipeline().addLast(new StringEncoder(StandardCharsets.UTF_8));
                            ch.pipeline().addLast(new ServerHandler());
                        }
                    }); //Gửi: ServerHandler → StringEncoder → Network

            ChannelFuture future = server.bind(port).sync();
            System.out.println("Server đang chạy tại cổng " + port);
            future.channel().closeFuture().sync();
        } finally {
            boss.shutdownGracefully();
            worker.shutdownGracefully();
        }
    }

    //Khi client gửi 5 dòng qua channel.writeAndFlush(), ServerHandler.channelRead0() được gọi 5 lần
    public static class ServerHandler extends SimpleChannelInboundHandler<String> {
        private final List<String> receivedLines = new ArrayList<>(); //Buffer lưu trữ 5 dòng dữ liệu từ client
        private ChannelHandlerContext ctx; //Context để gửi phản hồi về client

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, String msg) throws Exception {
            this.ctx = ctx;
            receivedLines.add(msg.trim());

            //server nhận đủ 5 dòng dữ liệu từ client, sau đó mới bắt đầu xử lý (giải mã, xác thực, quét subdomain)
            if (receivedLines.size() >= 5) {
                String rawMessage = receivedLines.get(0);
                String signature = receivedLines.get(1); //Nhận chữ ký
                String encryptedPubKey = receivedLines.get(2); //Nhận public key mã hóa
                String encryptedAESKey = receivedLines.get(3); //Nhận AES key mã hóa
                String encryptedIV = receivedLines.get(4); //Nhận IV mã hóa → Trigger xử lý

                //Giải mã AES key và IV. Dùng private key server giải mã AES key và IV
                PrivateKey privateKeyServer = RSAUtil.loadPrivateKey("server_keys/private_key_server.pem");
                byte[] aesKey = RSAUtil.decryptRSA(encryptedAESKey, privateKeyServer);
                byte[] iv = RSAUtil.decryptRSA(encryptedIV, privateKeyServer);

                //Giải mã public key client. Dùng AES key và IV vừa giải mã để giải mã public key client
                byte[] pubKeyClientBytes = AESCBC.decrypt(encryptedPubKey, aesKey, iv);
                PublicKey publicKeyClient = KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(pubKeyClientBytes));

                //Xác thực chữ ký, kiểm tra chữ ký có khớp với mess và public key client không
                boolean verified = VerifySignature.verify(rawMessage, signature, publicKeyClient);

                if (verified) {
                    send("Chữ ký xác thực thành công.");
                    System.out.println("Đã xác minh. Bắt đầu quét subdomain...");

                    //Quét subdomain (nếu xác thực thành công), load danh sách subdomain từ wordlist.txt
                    InputStream is = getClass().getClassLoader().getResourceAsStream("wordlist.txt");
                    if (is == null) throw new FileNotFoundException("Không tìm thấy wordlist.txt trong resources");

                    List<String> domains = new BufferedReader(
                            new InputStreamReader(is, StandardCharsets.UTF_8)
                    ).lines().toList();

                    domains = domains.subList(0, Math.min(300, domains.size())); //Giới hạn tối đa 300 subdomain
                    List<String> found = new ArrayList<>();

                    //Kiểm tra từng subdomain bằng HTTPS request
                    for (String sub : domains) {
                        String url = "https://" + sub + "." +rawMessage;
                        if (isAlive(url)) found.add(url);
                    }

                    if (found.isEmpty()) {
                        send("Không tìm thấy subdomain.");
                    } else {
                        send("Subdomain tồn tại:");
                        for (String f : found) send(f);
                    }

                } else {
                    send("Chữ ký sai. Hủy bỏ.");
                }

                receivedLines.clear();
            }
        }

        //Gửi phản hồi. Helper method để gửi message về client
        private void send(String msg) {
            ctx.writeAndFlush(msg + "\n");
        }

        //Kiểm tra subdomain. Gửi GET request với timeout 1 giây
        private static boolean isAlive(String url) {
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
                conn.setConnectTimeout(1000);
                conn.setReadTimeout(1000);
                conn.setRequestMethod("GET");
                int code = conn.getResponseCode();
                conn.disconnect();
                return code < 400; //Subdomain tồn tại nếu HTTP status < 400
            } catch (Exception e) {
                return false;
            }
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            System.err.println("Lỗi Server: " + cause.getMessage());
            ctx.close();
        }
    }
}
