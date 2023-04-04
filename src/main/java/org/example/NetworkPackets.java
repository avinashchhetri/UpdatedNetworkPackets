package org.example;


import org.pcap4j.core.*;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;

public class NetworkPackets extends JFrame {

    public static void main(String[] args) throws PcapNativeException, NotOpenException {

        PacketReader listener = new PacketReader();
        listener.addEventListener();
    }


}
