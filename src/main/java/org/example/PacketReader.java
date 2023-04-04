package org.example;

import org.pcap4j.core.*;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class PacketReader {

    public void Packet(File file, DefaultTableModel tableModel) throws PcapNativeException, NotOpenException, IOException {
        String pcapFile = file.getPath();
        String outputDir ="ChaosGeneratedFile";
        String[] command = {
                "bash",
                "-c",
                "chaosreader -r " + pcapFile + " -D " + outputDir
        };
        Path outputPath = Paths.get(outputDir);
        if (!Files.exists(outputPath)){
            Files.createDirectories(outputPath);
        }
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String deatils;
        while ((deatils = bufferedReader.readLine()) != null){
            System.out.println(deatils);
        }

        String fileName = "/home/avinash/Desktop/Rewara/UpdatedNetworkPackets/ChaosGeneratedFile/session_0003.http.html";
        try{
            File file1 =  new File(fileName);
            BufferedReader br = new BufferedReader((new FileReader(file1)));
            String line;
            while((line = br.readLine()) != null){
                if (line.contains("<font") && line.contains("color=\"red\"")) {
                    StringBuilder redContentBuilder = new StringBuilder();
                    redContentBuilder.append(line.replaceAll("(?i)<font[^>]*>|</font[^>]*>", ""));

                    // reads all the lines inside the font tag
                    while (!(line = br.readLine()).contains("</font>")) {
                        redContentBuilder.append(line);
                    }

                    // add the final line inside the font tag
//                    String redContent = String.valueOf(redContentBuilder.append(line.replaceAll("(?i)<font[^>]*>|</font[^>]*>", "")));
                    tableModel.addRow(new Object[]{redContentBuilder, ""});
//                    System.out.println(redContentBuilder);
                }
                if (line.contains("<font") && line.contains("color=\"blue\"")){
//                    System.out.println(line);
                    StringBuilder blueContentBuilder = new StringBuilder();
                    blueContentBuilder.append(line.replaceAll("(?i)<font[^>]*>|</font[^>]*>",""));
                    while (!(line = br.readLine()).contains("</font>")) {
                        blueContentBuilder.append(line);
                    }
//                    String blueContent = blueContentBuilder.toString().replaceAll("(?i)<font[^>]*>|</font[^>]*>", "");
                    tableModel.addRow(new Object[]{"", blueContentBuilder});
//                    System.out.println(blueContentBuilder);
                }
            }
            br.close();
        }catch (IOException e){
            System.out.println("Error Reading File: " + e.getMessage());
        }

    }

    public void addEventListener(){
        JFrame frame = new JFrame("PcapReader");
        frame.setVisible(true);
        frame.setSize(400,300);
        frame.setLayout(new BorderLayout());
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JPanel panel = new JPanel();

        JButton buttonFile = new JButton("File");
        JButton buttonParse = new JButton("Parse");
        panel.add(buttonParse);

        DefaultListModel<String> listModel = new DefaultListModel<>();
        JList<String> streamList = new JList<>(listModel);
        JScrollPane scrollPane = new JScrollPane(streamList);

        DefaultTableModel tableModel = new DefaultTableModel(new Object[]{"SRC", "DEST"},0);
        JTable table = new JTable(tableModel);
        JScrollPane scrollPaneTable = new JScrollPane(table);

        panel.add(scrollPaneTable, BorderLayout.CENTER);
        panel.add(buttonFile);
        frame.add(panel, BorderLayout.NORTH);
        frame.add(scrollPaneTable, BorderLayout.CENTER);

        buttonFile.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("Choose pcap file");
                fileChooser.setFileFilter(new FileNameExtensionFilter("pcap files", "pcap"));

                int result = fileChooser.showOpenDialog(null);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File selectedFile = fileChooser.getSelectedFile();
                    try {
                        Packet(selectedFile,tableModel);
                    } catch (PcapNativeException | NotOpenException | IOException exception) {
                        throw new RuntimeException(exception);
                    }
                } else {
                    System.out.println("File selection canceled.");
                }

            }
        });

        buttonParse.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                for(int i = 0 ; i < table.getRowCount(); i++){
                    Object redContent = table.getValueAt(i,0);
//                    System.out.println(redContent.toString().split("\\r\\n"));

                    String[] lines = redContent.toString().split("\\r\\n");

                    String[] response = lines[0].split("\\s");
                    String method = response[0];
                    String uri = response[1];
                    String httpVersion = response[2];
                    String host = response[3];

                    Map<String, String> headers = new HashMap<>();
                    for(int j =1; j< lines.length; j++){
                        String[] header = lines[i].split(":\\s");
                        headers.put(header[0],header[1]);
                    }
                    String[] parsedData = new String[6];
                    parsedData[0] = "Method: " + method;
                    parsedData[1] = "URI: " + uri;
                    parsedData[2] = "HTTP Version: " + httpVersion;
                    parsedData[3] = "Host: " + host;
                    parsedData[4] = "User-Agent: " + headers.get("User-Agent");
                    parsedData[5] = "Accept: " + headers.get("Accept");

                    for(String data :parsedData){
                        tableModel.addRow(new Object[]{data});
                    }
                }
//                for(int i=0; i<table.getRowCount();i++){
//                    Object blueContent = table.getRowCount();
////                    System.out.println(tableModel);
//                }
            }
        });
    }

}
