//Copyright (C) 2014, 2015 Patric R.

//Licensed to the Apache Software Foundation (ASF) under one
//or more contributor license agreements.  See the NOTICE file
//distributed with this work for additional information
//regarding copyright ownership.  The ASF licenses this file
//to you under the Apache License, Version 2.0 (the
//"License"); you may not use this file except in compliance
//with the License.  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing,
//software distributed under the License is distributed on an
//"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
//KIND, either express or implied.  See the License for the
//specific language governing permissions and limitations
//under the License.

package icqexport;

import java.awt.Desktop;
import java.io.BufferedWriter;
import java.io.EOFException;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import com.google.common.base.Charsets;
import com.google.common.base.Joiner;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.TreeMultimap;
import com.google.common.html.HtmlEscapers;
import com.mindprod.ledatastream.LERandomAccessFile;

/**
 * ICQExport - exports ICQ database files (prior to version 2003b) to HTML
 * 
 * Quickly hacked together...
 * 
 * @author Patric
 *
 */
public class ICQExport {

	public static byte[] EVENT_SIG = new byte[] { 0x23, (byte) 0xA3, (byte) 0xDB,
			(byte) 0xDF, (byte) 0xB8, (byte) 0xD1, 0x11, (byte) 0x8A, 0x65,
			0x00, 0x60, 0x08, 0x71, (byte) 0xA3, (byte) 0x91 };

	public static byte[] LONG_MESSAGE_SIG = new byte[] { (byte) 0x3b, (byte) 0xc1,
			(byte) 0x5c, (byte) 0x5c, (byte) 0x95, (byte) 0xd3, (byte) 0x11,
			(byte) 0x8d, (byte) 0xd7, 0x00, 0x10, 0x4b, (byte) 0x06,
			(byte) 0x46, 0x2e };

	static class Message implements Comparable<Message> {
		String text;
		Date timestamp;
		boolean received = true;

		public Message(String text, Date timestamp, boolean received) {
			super();
			this.text = text;
			this.timestamp = timestamp;
			this.received = received;
		}

		@Override
		public String toString() {
			return text;
		}

		@Override
		public int compareTo(Message o) {
			return o.timestamp.compareTo(timestamp);
		}

	}

	public static void main(String[] args) throws IOException {
		System.out
				.println("ICQExport - exports ICQ database files (prior to version 2003b) to HTML");

		File datFile = null;
		if (args.length > 0) {
			datFile = new File(args[0]);
		} else {
			JFileChooser chooser = new JFileChooser();
			chooser.setDialogTitle("Choose ICQ database file (prior to version 2003b) which should be exported");
			FileNameExtensionFilter filter = new FileNameExtensionFilter(
					"ICQ database files", "dat");
			chooser.setFileFilter(filter);
			int returnVal = chooser.showOpenDialog(null);
			if (returnVal == JFileChooser.APPROVE_OPTION) {
				datFile = chooser.getSelectedFile();
			} else
				System.exit(1);
		}

		System.out.println("Processing dat file");

		LERandomAccessFile datIn = new LERandomAccessFile(datFile, "r");
		byte[] sig = new byte[15];
		Map<String, Map<String, String>> userData = Maps
				.<String, Map<String, String>> newHashMap();

		TreeMultimap<String, Message> msgs = TreeMultimap.create();

		try {
			while (true) {
				if (datIn.read(sig) != sig.length)
					break;
				if (Arrays.equals(sig, EVENT_SIG) || Arrays.equals(sig, LONG_MESSAGE_SIG)) {
					long startPos = datIn.getFilePointer() - 0x1c;
					datIn.seek(startPos);
					int size = datIn.readInt();
					if (size < 0x20) {
						// System.out.println("Warning: suspicious entry size: "
						// + size + " @ " + startPos);
						datIn.skipBytes(0x0a);
						continue;
					}
					datIn.skipBytes(0x8);
					byte entryType = datIn.readByte();
					datIn.skipBytes(15);
					datIn.readShort();
					int flags = datIn.readInt();

					if (entryType == (byte) 0xE0 || entryType == (byte) 0x50) {
						int subType = datIn.readShort();
						int uin = datIn.readInt();
						String msgText = readASCII(datIn);
						if (msgText.indexOf((char) 0x00) >= 0) {
							// System.out.println("possible corrupt entry @ "
							// + startPos + " [msgtext: " + msgText + "]");
							continue;
						}
						int status = datIn.readInt();
						int sentOrReceived = datIn.readInt();
						datIn.readShort();
						long ts = datIn.readInt();
						Date tsDate = new java.util.Date(ts * 1000L);
						msgs.put(uin + "", new Message(msgText, tsDate,
								sentOrReceived == 0));
					} else if (entryType == (byte) 0xa0) {
						int subType = datIn.readShort();
						int uin = datIn.readInt();
						String url = readASCII(datIn);
						url = url.replaceAll("" + (char) 0xFE, " - ");
						int status = datIn.readInt();
						int sentOrReceived = datIn.readInt();
						datIn.readShort();
						long ts = datIn.readInt();
						Date tsDate = new java.util.Date(ts * 1000L);
						msgs.put(uin + "", new Message(url, tsDate,
								sentOrReceived == 0));
					} else if (entryType == (byte) 0xE5) {
						try {

							Map<String, String> properties = readProperties(
									datIn, startPos);
							if (properties.containsKey("UIN")) {
								userData.put(properties.get("UIN"), properties);
							} else {
								System.out
										.println("No UIN found inside properties!");
							}
						} catch (Exception e) {
							// e.printStackTrace(System.err);
						}
					}

				} else {
					datIn.seek(datIn.getFilePointer() - 14);
				}

			}
		} catch (EOFException e) {

		}

		System.out.println(msgs.size()
				+ " messages extracted. Writing output files...");
		File indexFile = writeIndexFile(userData, msgs);

		for (String UIN : msgs.keySet()) {
			writeMessageFile(UIN, userData, msgs);
		}

		System.out.println("Done!");

		if (Desktop.isDesktopSupported()) {

			Desktop.getDesktop().browse(indexFile.toURI());

		}

	}

	private static void writeMessageFile(String UIN,
			Map<String, Map<String, String>> userData,
			TreeMultimap<String, Message> msgs) throws IOException {
		File outDir = new File("html");
		outDir.mkdirs();
		File indexFile = new File(outDir, UIN + ".html");
		String nick =UIN;
		if(userData.get(UIN) != null)
		 nick = userData.get(UIN).get("NickName");

		BufferedWriter bw = new BufferedWriter(new FileWriter(indexFile));

		bw.write("<html><body style='font-family: monospace'><h1>Message log with "
				+ nick + " (UIN " + UIN + ")</h1>");

		bw.write("<br>");
		for (Message msg : msgs.get(UIN).descendingSet()) {
			String text = HtmlEscapers.htmlEscaper().escape(msg.text);
			text = text.replaceAll("\r\n", "<br>");
			if (msg.received) {
				bw.write("<div style='color:#000080'>[" + msg.timestamp
						+ "]   " + nick + ": " + text + "</div>");
			} else {
				bw.write("<div style='color:#008000'>[" + msg.timestamp
						+ "]   me: " + text + "</div>");
			}
			bw.newLine();
		}

		bw.write("<h2>Properties:</h2><br>");
		if(userData.get(UIN) != null) {
			for (Entry<String, String> entry : userData.get(UIN).entrySet()) {
				if (!"".equals(entry.getValue())) {
					bw.write(entry.getKey() + ":" + entry.getValue() + "<br>");
				}
			}
		}
		else
		{
			bw.write("INFO: No user data found in the database for this UIN (potentially not 'authorized friend' or corrupted database)");
		}

		bw.write("<hr><i>exported by ICQExport</i></body></html>");
		bw.close();
	}

	private static File writeIndexFile(
			Map<String, Map<String, String>> userData,
			TreeMultimap<String, Message> msgs) throws IOException {
		File outDir = new File("html");
		outDir.mkdirs();
		File indexFile = new File(outDir, "index.html");
		BufferedWriter bw = new BufferedWriter(new FileWriter(indexFile));

		bw.write("<html><body><table><tr><th>UIN</th><th>Nickname</th><th>Last seen online</th><th># Messages</tr>");
		for (String UIN : msgs.keySet()) {
			Map<String, String> props = userData.get(UIN);
			if(props != null) {
				String lastOnlineStr = "Unknown";
				if (props.containsKey("LastOnlineTime")) {
					Date lastOnline = new Date(
							new Long(props.get("LastOnlineTime")).longValue() * 1000L);
					lastOnlineStr = lastOnline.toString();
				}
				bw.write("<tr><td><a href=\"" + UIN + ".html\">" + UIN
						+ "</TD>+<TD>" + props.get("NickName") + "</TD><TD>"
						+ lastOnlineStr + "</TD><TD>" + msgs.get(UIN).size()
						+ "</TD></TR>");
			}
			else
			{
				bw.write("<tr><td><a href=\"" + UIN + ".html\">" + UIN
						+ "</TD>+<TD><i>User data missing in database</i></TD><TD>"
						+ "</TD><TD>" + msgs.get(UIN).size()
						+ "</TD></TR>");
			}
		}
		bw.write("</table><hr><i>exported by ICQExport</i></body></html>");
		bw.close();
		return indexFile;
	}

	private static Map<String, String> readProperties(LERandomAccessFile datIn,
			long startPos) throws IOException {
		Map<String, String> props = Maps.newHashMap();
		datIn.seek(startPos + 0x2c);
		int numberOfWavEntries = datIn.readInt();
		for (int i = 0; i < numberOfWavEntries; i++) {
			datIn.readShort();
			datIn.readInt();
			datIn.readInt();
			int len = datIn.readShort();
			datIn.skipBytes(len);
		}
		datIn.readShort();
		int propertyBlockCount = datIn.readInt();
		for (int i = 0; i < propertyBlockCount; i++) {
			datIn.readShort();
			int propertyCount = datIn.readInt();
			for (int w = 0; w < propertyCount; w++) {
				String propName = readASCII(datIn);
				int propType = datIn.readByte();
				String value = null;
				switch (propType) {
				case 107:
					value = readASCII(datIn);
					break;
				case 100:
					value = datIn.readUnsignedByte() + "";
					break;
				case 101:
					value = datIn.readByte() + "";
					break;
				case 102:
					value = datIn.readUnsignedShort() + "";
					break;
				case 103:
					value = datIn.readShort() + "";
					break;
				case 104:
					value = datIn.readInt() + ""; // should be unsigned
					break;
				case 105:
					value = datIn.readInt() + "";
					break;
				case 109:
					int subListPropCount = datIn.readInt();
					byte type = datIn.readByte();
					switch (type) {
					case 0x6b:
						List<String> subProps = Lists.newArrayList();
						for (int x = 0; x < subListPropCount; x++) {
							subProps.add(readASCII(datIn));
						}
						value = Joiner.on(" ").join(subProps);
						break;
					case 0x6e:
						throw new UnsupportedOperationException();

					default:
						throw new UnsupportedOperationException();

					}
					break;
				case 111:
					throw new UnsupportedOperationException();

				default:
					throw new IllegalStateException("Invalid property block @ "
							+ startPos);
				}

				props.put(propName, value);
			}

		}
		return props;
	}

	private static String readASCII(LERandomAccessFile datIn)
			throws IOException {
		int length = datIn.readShort();
		if (length <= 0)
			return "";
		byte[] msg = new byte[length - 1];
		datIn.read(msg);
		String msgText = new String(msg, Charsets.ISO_8859_1);
		datIn.skipBytes(1); // skip 0x00 separator
		return msgText;
	}

}
