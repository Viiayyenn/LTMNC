package Client;

import Utils.AESCBC;
import Utils.GenerateSignature;
import Utils.RSAUtil;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.LineBasedFrameDecoder;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Scanner;

public class ClientNetty {
    //Sử dụng port 2929 để kết nối đến server
    public static void main(String[] args) throws Exception {
        new ClientNetty().start("localhost", 2929);
    }
   //Khởi tạo và nhập dữ liệu từ bàn phím, ví dụ: github.com
    public void start(String host, int port) throws Exception {
        Scanner sc = new Scanner(System.in);
        System.out.print("Nhập domain để kiểm tra subdomain: ");
        String domain = sc.nextLine();
        String rawMessage = domain;

        //Load các khóa
        PrivateKey privateKeyClient = RSAUtil.loadPrivateKey("client_keys/private_key_client.pem"); //Load private key từ file PEM của client để ký
        PublicKey publicKeyClient = RSAUtil.loadPublicKey("client_keys/public_key_client.pem"); //Load public key của client để server xác thực
        PublicKey publicKeyServer = RSAUtil.loadPublicKey("server_keys/public_key_server.pem"); //Load public key của server để mã hóa

        //Tạo chữ ký số, Ký domain bằng private key của client
        String signature = GenerateSignature.sign(rawMessage, privateKeyClient);

        //Tạo khóa AES 128-bit ngẫu nhiên
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey aesKey = keyGen.generateKey();
        byte[] aesKeyBytes = aesKey.getEncoded();
        byte[] iv = AESCBC.generateIV();

        //Mã hóa public key client bằng AES
        String encryptedPubKey = AESCBC.encrypt(publicKeyClient.getEncoded(), aesKeyBytes, iv);
        String encryptedAESKey = RSAUtil.encryptRSA(aesKeyBytes, publicKeyServer); //Mã hóa AES key bằng RSA (public key server)
        String encryptedIV = RSAUtil.encryptRSA(iv, publicKeyServer); //Mã hóa IV bằng RSA (public key server)

        EventLoopGroup group = new NioEventLoopGroup();
        try {
            Bootstrap client = new Bootstrap();
            client.group(group)
                    .channel(NioSocketChannel.class)
                    .handler(new ChannelInitializer<>() {
                        @Override
                        protected void initChannel(Channel ch) { //Gửi đi: Data → StringEncoder → Network
                            ch.pipeline().addLast(new StringEncoder(StandardCharsets.UTF_8));
                            ch.pipeline().addLast(new LineBasedFrameDecoder(8192));
                            ch.pipeline().addLast(new StringDecoder(StandardCharsets.UTF_8));
                            ch.pipeline().addLast(new ClientHandler());
                        }
                    }); //Nhận về: Network → LineBasedFrameDecoder → StringDecoder → ClientHandler

            Channel channel = client.connect(host, port).sync().channel();

            //Kết nối và gửi dữ liệu
            channel.writeAndFlush(rawMessage + "\n"); //gửi tin nhắn
            channel.writeAndFlush(signature + "\n"); //Chữ ký số
            channel.writeAndFlush(encryptedPubKey + "\n"); //Public key client đã mã hóa AES
            channel.writeAndFlush(encryptedAESKey + "\n"); //AES key đã mã hóa RSA
            channel.writeAndFlush(encryptedIV + "\n"); //IV đã mã hóa RSA

            channel.closeFuture().sync();

        } finally {
            group.shutdownGracefully();
        }
    }

    //Mỗi khi nhận được dữ liệu từ Server thì sẽ in ra màn hình console nội dung Server gửi về
    public static class ClientHandler extends SimpleChannelInboundHandler<String> {
        @Override
        protected void channelRead0(ChannelHandlerContext ctx, String msg) {
            System.out.println("Server: " + msg.trim());
        }

        //Khi có lỗi xảy ra (mất kết nối, timeout, v.v.) thì in thông báo lỗi và đóng kết nối để giải phóng tài nguyên
        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            System.err.println("Lỗi ClientNetty: " + cause.getMessage());
            ctx.close();
        }
    }
}
