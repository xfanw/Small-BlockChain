/************************************
 * 1. Frank Wang, Oct 31, 2019
 * 2. Java Version: 1.8.0_172
 * 3. command line instructions:
		javac Blockchain.java
 * 4. in seperate shell windows:
		java Blockchain
   4.1 or use master.batch
   
 * 5. List of Files need for running the program:
		Blockchain.java
		BlockInput0.txt
		BlockInput1.txt
		BlockInput2.txt
 * 6. Notes
		1) All CONSTANT values are defined in the Blockchain class, which is easy to modify in one place;
		2) All static functions  are defined in the Blockchain class;
		3) Console input is not case sensitive, but do not have other bug prevent tech, so do't do too crazy on the input
 ************************************/





import java.util.*;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;

// public-private keypair generater
import java.security.*;	//Keypair, Private, Public, Signature, SecureRandom ...
import java.security.spec.*;	// convert string back to pubKey
//import javax.crypto.Cipher;

import java.security.MessageDigest;
//import java.util.Scanner;
import javax.xml.bind.DatatypeConverter;
//import java.util.Arrays;

/* CDE: The JAXB libraries: */
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
// even though we have util.*, we still want to make sure these have been inmported
//import java.util.Date;
//import java.util.Random;
//import java.util.UUID;
import java.text.*;
@XmlRootElement
class BlockRecord{
	// Header
	
	// add when creating
	String BlockID;			// UUID
	String CreatingProcess;
	String TimeStamp;
	String SignedSHA256;	// Base64 sign 	byte[] signedBlockID;	// Use private key of creating process to sign	
	
	// add when work
	String BlockNum;		// The order in the final verified Blockchain, starting from 1
	String VerificationProcessID;
	String PreviousHash;	// SHA256String of previous block
	String SHA256String;	// SHA256 of current block
	String Seed;	
	
	// records
	String Fname;
	String Lname;
	String SSNum;
	String DOB;
	String Diag;
	String Treat;
	String Rx;
	
	BlockRecord(){}
	BlockRecord(String s){
		SignedSHA256 = "[B@5f150435" ; // Verification procees SignedSHA-256-String 
		SHA256String = "63b95d9c17799463acb7d37c85f255a511f23d7588d871375d0119ba4a96a";
		VerificationProcessID = "1";
		//PreviousHash = "From the previous block in the chain" ;
		//<Seed> Your random 256 bit string </Seed> <!-- guess the value to complete the work-->
		BlockNum = "1";
		BlockID = "0";
		String seed;
		CreatingProcess = "0";
		TimeStamp = "2017-09-01.10:26:35.0000";
		//<DataHash> The creating process SHA-256 hash of the input data </DataHash> <!-- for auditing if Secret Key exposed -->
		Fname = "Joseph";
		Lname = "Ng";
		DOB = "1995.06.22";
		SSNum = "987-65-4321";
		Diag = "Measels";
		Treat = "Bedrest";
		Rx = "aspirin";	
	}
	
	/* Examples of accessors for the BlockRecord fields. Note that the XML tools sort the fields alphabetically
	by name of accessors, so A=header, F=Indentification, G=Medical: */
	//Header
	public String getASHA256String() {return SHA256String;}
	@XmlElement
	public void setASHA256String(String SH){this.SHA256String = SH;}
	
	public String getASignedSHA256() {return SignedSHA256;}
	@XmlElement
	public void setASignedSHA256(String SH){this.SignedSHA256 = SH;}
	
	public String getATimeStamp() {return TimeStamp;}
	@XmlElement
	public void setATimeStamp(String TS){this.TimeStamp = TS;}

	public String getACreatingProcess() {return CreatingProcess;}
	@XmlElement
	public void setACreatingProcess(String CP){this.CreatingProcess = CP;}

	public String getAVerificationProcessID() {return VerificationProcessID;}
	@XmlElement
	public void setAVerificationProcessID(String VID){this.VerificationProcessID = VID;}

	public String getABlockID() {return BlockID;}
	@XmlElement
	public void setABlockID(String BID){this.BlockID = BID;}
		
	public String getABlockNum() {return BlockNum;}
	@XmlElement
	public void setABlockNum(String bn){this.BlockNum = bn;}
	
	public String getAPrevHash() {return PreviousHash;}
	@XmlElement
	public void setAPrevHash(String SH){this.PreviousHash = SH;}
	
	public String getASeed() {return Seed;}
	@XmlElement
	public void setASeed(String seed){this.Seed = seed;}
	//records
	
	public String getFSSNum() {return SSNum;}
	@XmlElement
	public void setFSSNum(String SS){this.SSNum = SS;}

	public String getFFname() {return Fname;}
	@XmlElement
	public void setFFname(String FN){this.Fname = FN;}

	public String getFLname() {return Lname;}
	@XmlElement
	public void setFLname(String LN){this.Lname = LN;}

	public String getFDOB() {return DOB;}
	@XmlElement
	public void setFDOB(String DOB){this.DOB = DOB;}

	public String getGDiag() {return Diag;}
	@XmlElement
	public void setGDiag(String D){this.Diag = D;}

	public String getGTreat() {return Treat;}
	@XmlElement
	public void setGTreat(String D){this.Treat = D;}

	public String getGRx() {return Rx;}
	@XmlElement
	public void setGRx(String D){this.Rx = D;}	

}

// This is from bc.java
// 1. right now I am woring on pubkeys, so I want processID and pubKey 10/29/19
class ProcessBlock{
	int processID;	
	PublicKey pubKey;
	// int port;  // in this assignment port can be easily calculated by Ports class and processID.
	// String IPAddress;	// this assignment will use local host
} 

// Port 4710+process number receives public keys (4710, 4711, 4712)
// Port 4820+process number receives unverified blocks (4820, 4821, 4822)
// Port 4930+process number receives updated blockchains (4930, 4931, 4932)
// Other ports at your discretion, but please use the same scheme: base+process number.
class Ports{
	public final static int KeyServerPortBase = 4710;
	public final static int UnverifiedBlockServerPortBase = 4820;
	public final static int BlockchainServerPortBase = 4930;
	public final static int TriggerServerPortBase = 5050;

	public static int KeyServerPort;
	public static int UnverifiedBlockServerPort;
	public static int BlockchainServerPort;
	public static int TriggerServerPort;

	public static void setPorts(){
		KeyServerPort = KeyServerPortBase + Blockchain.PID ;
		UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + Blockchain.PID;
		BlockchainServerPort = BlockchainServerPortBase + Blockchain.PID ;
		TriggerServerPort = TriggerServerPortBase + Blockchain.PID ;
	}
}

class PublicKeyWorker extends Thread { // Class definition
	Socket sock; // Class member, socket, local to Worker.
	PublicKeyWorker (Socket s) {sock = s;} // Constructor, assign arg s to local sock
	PublicKey RestoredKey;
	public void run(){
		try{
			BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			// only send 1 line of string 
			// to avoid possibale data lost
			String data = in.readLine ();	  
			//System.out.println("Got string: " + data);

			// parse data to PID and pubKey, and ip?
			String[] tokens = data.split(" ");
			int index = Integer.parseInt(tokens[0]);
			String stringKey = tokens[1];
			//System.out.println(stringKey);
			try{
				// CONVERT string Key back to public key 	// from BlockI
				byte[] bytePubkey2  = Base64.getDecoder().decode(stringKey);
				//System.out.println("Key in Byte[] form again: " + bytePubkey2);

				X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(bytePubkey2);
				KeyFactory keyFactory = KeyFactory.getInstance("RSA");
				RestoredKey = keyFactory.generatePublic(pubSpec);
				
				// for each record received, create a tmp object and push it to the ProcessList;
				// we donot know the order in the list.
				Blockchain.PBlock[index] = new ProcessBlock();
				Blockchain.PBlock[index].processID = index;
				Blockchain.PBlock[index].pubKey = RestoredKey;		
			}catch(Exception e){
				System.out.println("fail to convert public key back");
			}
			
	
			
			sock.close(); 
		} catch (IOException x){x.printStackTrace();}
	}
}

class PublicKeyServer implements Runnable {    
  public void run(){
    int q_len = 6;
    Socket sock;
    System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
	Blockchain.printToLog("Process: " +Blockchain.PID +" : Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
    try{
      ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);
      while (true) {
		sock = servsock.accept();
		new PublicKeyWorker (sock).start(); 
      }
    }catch (IOException ioe) {System.out.println(ioe);}
  }
}

class TriggerWorker extends Thread { // Class definition
	Socket sock; // Class member, socket, local to Worker.
	TriggerWorker (Socket s) {sock = s;} // Constructor, assign arg s to local sock
	public void run(){
		try{
			BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			String data = in.readLine ();
			//System.out.println(data);
			if (Boolean.parseBoolean(data)){
				Blockchain.trigger = true;
			}
			sock.close(); 
		} catch (Exception x){x.printStackTrace();}
	}
}

class TriggerServer implements Runnable {    
  public void run(){
    int q_len = 6;
    Socket sock;
    System.out.println("Starting Trigger Server input thread using " + Integer.toString(Ports.TriggerServerPort));
	Blockchain.printToLog("Process: " +Blockchain.PID +" : Starting Trigger Server input thread using " + Integer.toString(Ports.TriggerServerPort));
    try{
      ServerSocket servsock = new ServerSocket(Ports.TriggerServerPort, q_len);
      while (true) {
		sock = servsock.accept();
		new TriggerWorker (sock).start(); 
      }
    }catch (IOException ioe) {System.out.println(ioe);}
  }
}

class UnverifiedBlockServer implements Runnable {
	BlockingQueue<BlockRecord> queue;
	
	UnverifiedBlockServer(BlockingQueue<BlockRecord> queue){
		this.queue = queue; // Constructor binds our prioirty queue to the local variable.
	}

  /* Inner class to share priority queue. We are going to place the unverified blocks into this queue in the order we get
     them, but they will be retrieved by a consumer process sorted by blockID. */ 

	class UnverifiedBlockWorker extends Thread { // Class definition
		Socket sock; // Class member, socket, local to Worker.
		UnverifiedBlockWorker (Socket s) {sock = s;} // Constructor, assign arg s to local sock
		
		public void run(){
			try{
				BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
				String data = "";
				String tmp = in.readLine();
				int pid = Integer.parseInt(tmp);
				String spliter = "</blockRecord>";
				while ((tmp = in.readLine()) != null){
					data = data + tmp + "\n";
				}
				
				//System.out.println("DataFrom PID: " + pid +"\n"+ data + "\n");
				//Blockchain.PBlock[pid].pubKey;
				
				String[] tokens = data.split(spliter);
				int size = tokens.length - 1;	// the data has an empty line at the end, so we will throw it
				//System.out.println(size + " blocks received\n");
				for (int i = 0; i < size ; i++){
					tokens[i] += spliter;
					//System.out.println("Record: "+(i+1)+"\n"+tokens[i]);
					BlockRecord tmpRecord = Blockchain.getBlockRecordFromXML(tokens[i]);					
					queue.put(tmpRecord);
				}
				//queue.put(data);
				sock.close(); 
			} catch (Exception x){
				System.out.println("xml to data error");
				//x.printStackTrace();
			}
		}
	}// end inner worker class
  
	public void run(){
		int q_len = 6; /* Number of requests for OpSys to queue */
		Socket sock;
		System.out.println("Starting the Unverified Block Server input thread using " + Integer.toString(Ports.UnverifiedBlockServerPort));
		
		try{
			ServerSocket servsock = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
			while (true) {
				sock = servsock.accept(); // Got a new unverified block
				new UnverifiedBlockWorker(sock).start(); // So start a thread to process it.
			}
		}catch (IOException ioe) {System.out.println(ioe);}
	}
}

/* We have received unverified blocks into a thread-safe concurrent access queue. Just for the example, we retrieve them
in order according to their blockID. Normally we would retreive the block with the lowest time stamp first, or? This
is just an example of how to implement such a queue. It must be concurrent safe because two or more threads modifiy it
"at once," (mutiple worker threads to add to the queue, and consumer thread to remove from it).*/

// Even though it is said to use BlockID, I used time stamp with process num and record num appended to it
// it wont get any same values 

class UnverifiedBlockConsumer implements Runnable {
	BlockingQueue<BlockRecord> queue;
	
	UnverifiedBlockConsumer(BlockingQueue<BlockRecord> queue){
		this.queue = queue; // Constructor binds our prioirty queue to the local variable.
	}

	public void run(){
		BlockRecord data;
		boolean isVerified = false;	
		
		System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");
		try{
			while(queue.size() > 0){	// if we have item in the unverified queue, 
										// 1. Consume from the incoming queue. 2. Do the work to verify. 3. Mulitcast new blockchain
			int bcSize = Blockchain.blockChain.size();
				data = queue.peek(); // Will blocked-wait on empty queue
 // System.out.println("unverified size: "+queue.size());	
  System.out.println("BlockChain size: "+bcSize);
//Blockchain.printToLog("Process: " +Blockchain.PID +" : BlockChain size: "+bcSize);
 // System.out.println("IsVarified: "+IsVerified(data));	
				// 1.1 verify if data is in the blockChain
				if (IsVerified(data)) {
					queue.take(); 		//remove first elemet
					continue;
				}	
System.out.println("unverified size: "+queue.size());
//Blockchain.printToLog("Process: " +Blockchain.PID +" : unverified size: "+queue.size());		
				// 1.2 verify SHA-256 hash
				String uuid = data.getABlockID();
				String signedSHA256 = data.getASignedSHA256();
				byte[] signedUUID = Base64.getDecoder().decode(signedSHA256);
				int processId = Integer.parseInt(data.getACreatingProcess().substring(7));
				//System.out.println(processId);
				
				// 1.3 verify signed BlockID with public key
				PublicKey currPubKey = Blockchain.PBlock[processId].pubKey;		
				boolean verify = verifySig(uuid.getBytes(), currPubKey, signedUUID);

				
				if (!verify){
					queue.take();	//remove first elemet
					System.out.println("You get a faked block\n");
					continue;
				}		
				
				// 2 Do the work
				boolean isDone = doTheWORK(data, bcSize);	
//System.out.println("Work is Done by : " + Blockchain.PID + isDone);		
				// 3. muticast 
				if (isDone && bcSize == Blockchain.blockChain.size()) {	// if the blockchain have not been modified
	
					// append to blockchain,  then multicate
					Blockchain.blockChain.put(data);
					String XMLChain = Blockchain.getXMLChain();
//System.out.println("Data Send: \n" +XMLChain);
					// send to each process in group, including us:
					Blockchain.MultiSendNewBlockChain(XMLChain);
					try{Thread.sleep(1000);}catch(Exception e){}	// wait for all the process finished receiving the records
				 } 
				Thread.sleep(1500); // For the example, wait for our blockchain to be updated before processing a new block
			}// end while
		}catch (Exception e) {System.out.println(e);}
	}// end run
	private boolean doTheWORK(BlockRecord data, int bcSize){
		String UB = "";
		boolean workIsDone = false;
		// 2.1 insert blockNum to the Block
		data.setABlockNum (String.valueOf(bcSize + 1));
		// 2.2 insert verifying ID to the Block
		data.setAVerificationProcessID (String.valueOf(Blockchain.PID));
		// 2.3 cancatenate 3 string(a, b, c) to ub
		// 2.3.a pre SHA256 string
		String prev256 = Blockchain.blockChain.peekLast().getASHA256String ();
		data.setAPrevHash(prev256);
		// 2.3.b blockRecord without header
		String cleanRecord =  data.getFFname() + data.getFLname() + data.getFSSNum()
							+ data.getFDOB () + data.getGDiag () + data.getGTreat ()
							+ data.getGRx ();				
		// generate random seed and do WORK			// from workB.java
		try {				
			while (true) {	
				String seed = randomAlphaNumeric(8);
				UB = prev256 + cleanRecord + seed;
				MessageDigest MD = MessageDigest.getInstance("SHA-256");
				byte[] bytesHash = MD.digest(UB.getBytes("UTF-8")); // Get the hash value
				String SHA256String = DatatypeConverter.printHexBinary(bytesHash); // Turn into a string of hex values
				//System.out.println("Hash is: " + SHA256String);
				int workNumber = Integer.parseInt(SHA256String.substring(0,4),16); // Left most 16bits to int
				//System.out.println("First 16 bits in Hex and Decimal: " + SHA256String.substring(0,4) +" and " + workNumber);

				if (workNumber < Blockchain.WORK_LOAD){	// puzzle solved
					//update current block
					data.setASeed(seed);
					data.setASHA256String ( SHA256String);	
					workIsDone = true;
					return workIsDone;
				} else if (workNumber < 3 * Blockchain.WORK_LOAD){ 	//periodically chech to see if the block is verified
					if(IsVerified(data)){
System.out.println("***********work is Done by other process***********");
Blockchain.printToLog("Process: " +Blockchain.PID +" : ***********work is Done by other process***********");
						break;			// if hase been verified, give up		
					}						
				}
			}		//end random string while			
		} catch (Exception e) {	e.printStackTrace();}
		// work is done	
		return workIsDone;	// here always false
	}
 	
	
			
// check if the data has been verified	
	private static boolean IsVerified(BlockRecord data) {	
		for (BlockRecord tmp : Blockchain.blockChain) {
			if (tmp.getABlockID().equals(data.getABlockID())) { // BlockID and time stamp are both unique in this program
				return true;
			}
		}
		return false;
	}

// generate a random string 	// from workB.java	
	public static String randomAlphaNumeric(int count) {
		StringBuilder builder = new StringBuilder();
		while (count-- != 0) {
			int character = (int)(Math.random()*Blockchain.ALPHA_NUMERIC_STRING.length());
			builder.append(Blockchain.ALPHA_NUMERIC_STRING.charAt(character));
		}
		return builder.toString();
	}	

// verify data 		//from BlockI.java
	public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initVerify(key);
		signer.update(data);

		return (signer.verify(sig));
	}	
}

// Incoming proposed replacement blockchains. Compare to existing. Replace if winner:
    
class BlockchainWorker extends Thread { // Class definition
	Socket sock; // Class member, socket, local to Worker.
	BlockchainWorker (Socket s) {sock = s;} // Constructor, assign arg s to local sock
	public void run(){
		try{
			BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			String data = "";
			String data2;
			boolean inBlock = false;
			String spliter = "</blockRecord>";
			while((data2 = in.readLine()) != null){
				data = data + data2 + "\n";
			}
//System.out.println("Data Received: \n" +data);
			// convert data to new block chain
			LinkedBlockingDeque<BlockRecord> newBC = new LinkedBlockingDeque<>();
			String[] tokens = data.split(spliter);
			int size = tokens.length - 1;	// the data has an empty line at the end, so we will throw it
//				int n = 0;
			// for (BlockRecord tmp : Blockchain.blockChain){
// System.out.println("OLD:  "+n+" verifiedID: "+ tmp.getAVerificationProcessID());	
			// n++;
			// }			
// System.out.println(size + " blocks received\n");
			for (int i = 0; i < size ; i++){
				tokens[i] += spliter;
				//System.out.println("Record: "+(i+1)+"\n"+tokens[i]);
				BlockRecord tmpRecord = Blockchain.getBlockRecordFromXML(tokens[i]);	
// System.out.println("received: " + i + " verified ID: "+ tmpRecord.getAVerificationProcessID());			
				newBC.put(tmpRecord);
			}
		
			if(newBC.size() > Blockchain.blockChain.size()){	// we always accept longer blockchain as verified.
				Blockchain.blockChain = newBC;
// System.out.println("Update blockChain\n");					
			}
		// n = 0;
			// for (BlockRecord tmp : Blockchain.blockChain){
// System.out.println("updated:  "+n+" verifiedID:"+ tmp.getAVerificationProcessID());	
			// n++;
			// }
		System.out.println("\n\t\t--NEW BLOCKCHAIN--\n\tOnly Time Stamp and verification ID\n");
		Blockchain.printToLog("Process: " +Blockchain.PID +" : \n\t\t--NEW BLOCKCHAIN--\n\tOnly Time Stamp and verification ID\n");
		String output = Blockchain.getXMLChain();
		for (BlockRecord tmp : Blockchain.blockChain){
			System.out.println(tmp.getATimeStamp()+ " Verification ID:"+tmp.getAVerificationProcessID());
			Blockchain.printToLog("Process: " +Blockchain.PID +" : " + tmp.getATimeStamp() + " Verification ID:" + tmp.getAVerificationProcessID());
		}
		//System.out.println("         --NEW BLOCKCHAIN--\n" + output + "\n\n");
		
		if (Blockchain.PID == 0){		// Process 0 write the blockchain to file every time it gets a new block chain
			Blockchain.WriteToFile(output);
		}
		sock.close(); 
		} catch (Exception x){x.printStackTrace();}
	}	
	
}

class BlockchainServer implements Runnable {
	public void run(){
		int q_len = 6; /* Number of requests for OpSys to queue */
		Socket sock;
		System.out.println("Starting the blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort));
		try{
			ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
			while (true) {
				sock = servsock.accept();
				new BlockchainWorker (sock).start(); 
			}
		}catch (IOException ioe) {System.out.println(ioe);}
	}
}
// Input thread to accept console input
class ConsoleInput implements Runnable {
	public void run(){
		while(true){
		String input = "";
			try{
				BufferedReader reader =
						   new BufferedReader(new InputStreamReader(System.in));
				input = reader.readLine();			
			}catch (IOException e){e.printStackTrace();}	

			char firstChar = Character.toUpperCase(input.charAt(0));

			switch(firstChar){
				case 'C':
					printCredit();
				break;
				case 'R':
					if (input.length() > 2){
						String fileName = input.substring(2);
						String records = Blockchain.generateBlockArrayFromFile(fileName);
						Blockchain.MultiSendUnverifiedBlocks(records);						
					}else{
						System.out.println("Enter a space and a fileName after R");
					}
				break;
				case 'V':
					if (input.length() > 2){
						String argument = input.substring(2);	
						if (argument.toLowerCase().equals("threshold")){
							verifyThreshold();
						}else if (argument.toLowerCase().equals("hash")){
							verifyHash();
						}else if (argument.toLowerCase().equals("signature")){
							verifySignature();
						}else{
							verifyWholeBlock();
						}
					}else{
						verifyWholeBlock();
					}
				break;				
				case 'L':
					printRecords();
				break;
				default:	
					// do nothing				
			}	
		}		
	}
	private void verifySignature(){
		System.out.println("I did not sign SHA256 with verification ID, however, I signed BlockID with creation ID");
		System.out.println("The verify process is in the WORK of each block.");
	}
	private void verifyHash(){
		for (BlockRecord tmp: Blockchain.blockChain){
			String UB = getNeededString(tmp);
			int blockNum = Integer.parseInt(tmp.getABlockNum());
	
			String SHA256String = Blockchain.getSHA256FromString(UB); 
		
			if (SHA256String.equals(tmp.getASHA256String())){	

				System.out.println("Block: " + blockNum + " is sucessfully verified.");
			} else if(blockNum > 1){		// first block do not need verify
				System.out.println(	"Blocks: 1 - " + (blockNum - 1) + "have been verified.\n"
								+ 	"Block: " + blockNum + " invalid: SHA256 hash does not match\n"
								+	"Block: " + (blockNum+1) + " following an invalid block");
			}

		}		
	}
	private void verifyThreshold(){
		for (BlockRecord tmp: Blockchain.blockChain){
			String UB = getNeededString(tmp);
			int blockNum = Integer.parseInt(tmp.getABlockNum());
			String SHA256String = Blockchain.getSHA256FromString(UB); 

			int workNumber = Integer.parseInt(SHA256String.substring(0,4),16);
			if (workNumber < Blockchain.WORK_LOAD){	

				System.out.println("Block: " + blockNum + " is sucessfully verified.");
			} else if(blockNum > 1){		// first block do not need verify
				System.out.println(	"Blocks: 1 - " + (blockNum - 1) + "have been verified.\n"
								+ 	"Block: " + blockNum + " invalid: SHA256 confirmed, but does not meet the work threshold\n"
								+	"Block: " + (blockNum+1) + " follow an invalid block");
			}

		}		
	}
	private void verifyWholeBlock(){
		for (BlockRecord tmp: Blockchain.blockChain){
			String UB = getNeededString(tmp);
			int blockNum = Integer.parseInt(tmp.getABlockNum());
			String SHA256String = Blockchain.getSHA256FromString(UB);

			int workNumber = Integer.parseInt(SHA256String.substring(0,4),16);
			if (workNumber < Blockchain.WORK_LOAD){	
				System.out.println("Block: " + blockNum + " is sucessfully verified.");
			} else if(blockNum > 1){		// first block do not need verify
				System.out.println("Fail to verify Block: " + blockNum);
				System.out.println("Block: " + (blockNum+1) + " follow an invalid block");
			}

		}
	}
	
	private String getNeededString(BlockRecord tmp){
		//find the 3 parts of a record
		String prev256 = tmp.getAPrevHash();
		String cleanRecord =  tmp.getFFname() + tmp.getFLname() + tmp.getFSSNum()
							+ tmp.getFDOB () + tmp.getGDiag () + tmp.getGTreat ()
							+ tmp.getGRx ();				
		String seed = tmp.getASeed();
		return prev256 + cleanRecord + seed;
	}
	
	private void printCredit(){
		// initialize all credit to 0;
		int[] credit = new int[Blockchain.NUM_PROCESS];
		for (int i = 0; i < Blockchain.NUM_PROCESS; i++){
			credit[i]=0;
		}
		//calc credit for each process
		for (BlockRecord tmp: Blockchain.blockChain){
			int pid = Integer.parseInt(tmp.getAVerificationProcessID());
			credit[pid]++;
		}
		for (int i = 0; i < Blockchain.NUM_PROCESS; i++){
			System.out.println("Process: " + i + " earned "+ credit[i] +" Credits\n");
		}
		
	}
	
	private void printRecords(){
		for (BlockRecord tmp: Blockchain.blockChain){
			System.out.println( "BlockNum: " + tmp.getABlockNum()
							+ " Time Stamp: "+ tmp.getATimeStamp()
							+ " Name: " + tmp.getFFname() + " " + tmp.getFLname()
							+ " Dianosis: " + tmp.getGDiag()
							+ " Treatment: " + tmp.getGTreat()
							//+ etc.	
			);
		}
	}
	
	
}
// Class bc for Blockchain
public class Blockchain {  
	// constants
	static String serverName = "localhost";
	static final BlockRecord FIRST_BLOCK = new BlockRecord(new String());
	static final int NUM_PROCESS = 3; // Set this to match your batch execution file that starts N processes with args 0,1,2,...N  
	static final String XML_HEADER = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
	static final int MAX_UNVERIFIED_QUEUE = 500;
	static final int PID_TRGGER = 2;
	static final int WORK_LOAD = 5;
	static final int MAX_BC_LENGTH = 10000;
	static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	
	
	// shared veriables
	static int PID = 0; // Our process ID
	static volatile boolean trigger = false;	// only use volatile can the trigger be updated in the wile loop	
	static KeyPair keyPair;
	// static PublicKey publicKey;	// this is what I wanted to marshal at beginning, but does not work
	// static String stringPubKey;	//  used for verify, but it canbe moved to main()	
	
	// most often used in different threads
	static public ProcessBlock[] PBlock = new ProcessBlock[NUM_PROCESS]; // One block to store info for each process.
	static BlockingQueue<BlockRecord> unverifiedQueue;
	static LinkedBlockingDeque<BlockRecord> blockChain = new LinkedBlockingDeque<>();
	
	
public static void main(String args[]){
    int q_len = 6; /* Number of requests for OpSys to queue. Not interesting. */
	
	PrivateKey privateKey;
	String stringPubKey = "";
	String cleanXMLBlock = "";
	 
	// get PID
    PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]); // Process ID	
    System.out.println("Frank's Blockchain Using processID: " + PID + "\n");
    
	//create a comparator based on time stamp
	Comparator<BlockRecord> blockComparator = new Comparator<BlockRecord>() {
		@Override
		public int compare(BlockRecord b1, BlockRecord b2) {
			int toReturn = 0;
			if (b1.TimeStamp.compareTo(b2.TimeStamp) < 0){
				toReturn = -1;
			}
			if (b1.TimeStamp.equals(b2.TimeStamp)){
				toReturn = 0;
			}
			if (b1.TimeStamp.compareTo(b2.TimeStamp) >0 ){
				toReturn = 1;
			}
			return toReturn;
		}
	};
	
	unverifiedQueue= new PriorityBlockingQueue<BlockRecord>(MAX_UNVERIFIED_QUEUE, blockComparator);
	blockChain.add(FIRST_BLOCK);
	// generate ports of current block and use those ports to listen.
	// later all processes will push message to desired ports.
    Ports.setPorts(); 
	
	if(PID == 0){
		try{
			BufferedWriter logWriter = new BufferedWriter( new FileWriter("BlockChainLog.txt") );
			logWriter.write("Frank's Block Chain Log file Start.\n");		
			logWriter.close();
		}catch(Exception e){System.out.println("Create log file error");}
	}
	
	// generate keypair	
	try{
		keyPair = generateKeyPair(PID);
		privateKey = keyPair.getPrivate();
		
      // convert public key into a string suitable for marshaling in XML	// from BlockI
		byte[] bytePubkey = keyPair.getPublic().getEncoded();
		stringPubKey = Base64.getEncoder().encodeToString(bytePubkey);		
	// read original file
	String fileName = "BlockInput"+PID+".txt";	
	cleanXMLBlock = generateBlockArrayFromFile(fileName); 
			// //******************verify xml string***********************
			// System.out.println(cleanXMLBlock);
			// // show the string of concatenated, individual xml blocks:
			// String xmlblock = XML_HEADER + "\n<blockledger>" + cleanXMLBlock + "</blockledger>";
			// System.out.println(xmlblock);		
	}
    catch (Exception e){System.out.println("unable to create key pair");}  
	
	new Thread(new TriggerServer()).start();
    new Thread(new PublicKeyServer()).start(); // New thread to process incoming public keys
    new Thread(new UnverifiedBlockServer(unverifiedQueue)).start(); // New thread to process incoming unverified blocks
    new Thread(new BlockchainServer()).start(); // New thread to process incomming new blockchains
    try{Thread.sleep(1000);}catch(Exception e){} // Wait for servers to start.
	
	if (PID == PID_TRGGER){
		trigger = true;
		MultiSendTrigger(); 	//change triggers of other process to true
	}
	
	while (!trigger){}	//wait for trigger process to trigger all multicast methods
			// //******************verify trigger ***********************
			//System.out.println("Trigger received");
			
	MultiSendPubKey(stringPubKey); 	// Multicast some new unverified blocks out to all servers as data
									// //******************verify public Key thread***********************
									// for(int i=0; i < 3; i++){
										// System.out.println(PBlock[i].processID+ "  "+ PBlock[i].pubKey);
									// }
	MultiSendUnverifiedBlocks(cleanXMLBlock); 	// send unverified blocks to all the process and save into priority queue
	try{Thread.sleep(1000);}catch(Exception e){}	// wait for all the process finished receiving the records
												// // ******************verify unverified Queue***********************												
													// int unverifiedQueueSize = unverifiedQueue.size();
													// for(int i = 0; i < unverifiedQueueSize; i++){
														// BlockRecord tmp = unverifiedQueue.poll();
														// System.out.println(tmp.getATimeStamp());
													// }													

    new Thread(new UnverifiedBlockConsumer(unverifiedQueue)).start(); // Start consuming the queued-up unverified blocks
	
	// till here , the basic is done.
	// from here will accept console input to do some extra work and this can be done use new thread
	new Thread(new ConsoleInput()).start();
	
  }

  // generate KeyPair    // from BlockI example
public static KeyPair generateKeyPair(long seed) throws Exception {
	KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
	SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
	rng.setSeed(seed);
	keyGenerator.initialize(1024, rng);

	return (keyGenerator.generateKeyPair());
}

// sign data 		//from BlockI.java
public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
	Signature signer = Signature.getInstance("SHA1withRSA");
	signer.initSign(key);
	signer.update(data);
	
	return (signer.sign());
}  

// read file and save it to a local block 	// this is from BlockInputE.java 
// read *.txt file from disk and convert all record to xml format without <XML header>
public static String generateBlockArrayFromFile(String fileName){
	String cleanBlock = "";
	try {
		try (BufferedReader br = new BufferedReader(new FileReader(fileName))) {
			String[] tokens = new String[7]; // each record has 7 parts:
						// fN, lN, DOB, SSN, Dx, Tx, Rx
			String stringXML;
			String InputLineStr;
			UUID idA;

			BlockRecord[] blockArray = new BlockRecord[20]; 
			int n = 0;

			while ((InputLineStr = br.readLine()) != null) {
				blockArray[n] = new BlockRecord();

				// update each block record
				// set uuid and time stamp. Well, time stamp does not make sense in this assignment, because all of them are created almost the same time.
			// UUID
				String uuid = UUID.randomUUID().toString();
				//System.out.println(uuid);
				blockArray[n].setABlockID(uuid);
			// sign UUDI with private key
				byte[] signedUUID = signData(uuid.getBytes(), keyPair.getPrivate());
				//System.out.println(signedUUID);				
					// // *****************verify signature**********************
					// boolean v = verifySig(uuid.getBytes(), keyPair.getPublic(), signedUUID);
					// System.out.println(v);
			// change signedUUID to SHA256 string
			  String SignedSHA256 = Base64.getEncoder().encodeToString(signedUUID);
			 // System.out.println("The signed SHA-256 string: " + SignedSHA256 + "\n");
			  blockArray[n].setASignedSHA256(SignedSHA256);
			//processID
				blockArray[n].setACreatingProcess("Process" + PID);

			// Time Stamp	// from BlockI.java
				Date date = new Date();
				String T1 = String.format("%1$tF.%1$tT", date);
				String TimeStampString = T1 + "." + ((PID + 1) * 1000 + (n + 1)); // No timestamp collisions!
				blockArray[n].setATimeStamp(TimeStampString);

				/* CDE put the file data into the block record: */
				tokens = InputLineStr.split(" +"); // Tokenize the input
				blockArray[n].setFSSNum(tokens[3]);
				blockArray[n].setFFname(tokens[0]);
				blockArray[n].setFLname(tokens[1]);
				blockArray[n].setFDOB(tokens[2]);
				blockArray[n].setGDiag(tokens[4]);
				blockArray[n].setGTreat(tokens[5]);
				blockArray[n].setGRx(tokens[6]);
				n++;
			}
						// ******************verify***********************
						// System.out.println(n + " records read.");
						// System.out.println("Names from input:");			
						// for(int i=0; i < n; i++){
							// System.out.println("  " + blockArray[i].getFFname() + " " +
							// blockArray[i].getFLname()+"  " + blockArray[i].getATimeStamp());
						// }
						// System.out.println("\n");
						
						// convert blockrecord to xml string
			JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
			Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
			StringWriter sw = new StringWriter();

			// CDE Make the output pretty printed:
			jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
			for(int i=0; i < n; i++){
				jaxbMarshaller.marshal(blockArray[i], sw);
			}
			String fullBlock = sw.toString();			
			cleanBlock = fullBlock.replace(XML_HEADER, "");	// always send cleanblock, but write to file using XMLblock
		//System.out.println("Clean Block:"+cleanBlock);
		} catch (IOException e) {e.printStackTrace();}
	} catch (Exception e) {	System.out.println("e");}
	return cleanBlock;
	
}

//send unverified blocks to other thread
public static void MultiSendUnverifiedBlocks (String cleanXMLBlock){ 
	Socket sock;
	PrintStream toServer;
	//System.out.println("Data to Send: \n" + cleanXMLBlock);
	try{
		for(int i=0; i< NUM_PROCESS; i++){
			sock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + i );
			toServer = new PrintStream(sock.getOutputStream());			
			toServer.println(PID + "\n" + cleanXMLBlock);
			toServer.flush();
			sock.close();
		} 
		Thread.sleep(1000); 
	}catch (Exception x) {x.printStackTrace ();}
}

//send public key to other thread
public static void MultiSendPubKey (String stringPubKey){ // Multicast some data to each of the processes.
	Socket sock;
	PrintStream toServer;
	
	try{
		for(int i=0; i< NUM_PROCESS; i++){// Send our key to all servers.
			//System.out.println("************sending to port: "+ (Ports.KeyServerPortBase + i));
			sock = new Socket(serverName, Ports.KeyServerPortBase + i );
			toServer = new PrintStream(sock.getOutputStream());
			toServer.println(PID +" "+stringPubKey);
			toServer.flush();
			sock.close();
		} 
		Thread.sleep(1000); 
	}catch (Exception x) {x.printStackTrace ();}
}

//send trigger to other thread
public static void MultiSendTrigger (){ 
	Socket sock;
	PrintStream toServer;

	try{
		for(int i=0; i< NUM_PROCESS; i++){
			//System.out.println("************sending triggrt "+trigger+" to port: "+ (Ports.TriggerServerPortBase + i));
			sock = new Socket(serverName, Ports.TriggerServerPortBase + i );
			toServer = new PrintStream(sock.getOutputStream());
			toServer.println(trigger);
			toServer.flush();
			sock.close();
		} 
		Thread.sleep(1000); 
	}catch (Exception x) {x.printStackTrace ();}
}

//send string Block Chain  to other thread
// this method will be called in threads unverified consumer
public static void MultiSendNewBlockChain (String newBlock){ 
	Socket sock;
	PrintStream toServer;

	try{
		for(int i=0; i< NUM_PROCESS; i++){			
			sock = new Socket(serverName, Ports.BlockchainServerPortBase + i );
			toServer = new PrintStream(sock.getOutputStream());
			toServer.println(newBlock);
			toServer.flush();
			sock.close();
		} 
		Thread.sleep(1000); 
	}catch (Exception x) {x.printStackTrace ();}
}

//convert xml to blockrecord
public static BlockRecord getBlockRecordFromXML(String xmlString){
	BlockRecord tmpRecord = new BlockRecord();
	try{
		JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
		Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
		StringReader reader = new StringReader(xmlString);
		tmpRecord = (BlockRecord) jaxbUnmarshaller.unmarshal(reader);

		//System.out.println("TimeStamp: " + tmpRecord.getATimeStamp()); // Show a piece of the new block object
	}catch(Exception e){System.out.println("Fail to convert xml to BlockRecord");}
	return tmpRecord;
}

//convert block chain to xml
public static String getXMLChain(){
	String cleanBlock = "";
	try{
		JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
		Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
		StringWriter sw = new StringWriter();

		// CDE Make the output pretty printed:
		jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
		for (BlockRecord tmp : Blockchain.blockChain){
			jaxbMarshaller.marshal(tmp, sw);
		}
		
		String fullBlock = sw.toString();			
		cleanBlock = fullBlock.replace(Blockchain.XML_HEADER, "");	// always send cleanblock, but write to file using XMLblock
	}catch (Exception e){e.printStackTrace();}
	return cleanBlock;
}
// get a SHA256 String from a string 
public static String getSHA256FromString(String UB){
	String SHA256String = "";
	try{			
		MessageDigest MD = MessageDigest.getInstance("SHA-256");
		byte[] bytesHash = MD.digest(UB.getBytes("UTF-8")); 
		SHA256String = DatatypeConverter.printHexBinary(bytesHash); 
	}catch (Exception e){e.printStackTrace();}
	return SHA256String;
}
// write to xml file, the block chain server will call it
public static void WriteToFile(String toWrite){
	try{
		BufferedWriter xmlWriter = new BufferedWriter( new FileWriter("BlockchainLedger.xml") );
		xmlWriter.write(XML_HEADER);	
		xmlWriter.write("\n<BlockLedger>" + toWrite + "</BlockLedger>");
		xmlWriter.close();
	} catch (Exception e){System.out.println("Fail to write file");}
}

// write to log file
public static void printToLog(String str) {
	try{
		BufferedWriter logWriter = new BufferedWriter( new FileWriter("BlockChainLog.txt", true) );
		logWriter.append(str);
		logWriter.append("\n");
		logWriter.close();
	}catch (IOException e){
		System.out.println("File Error.");
	}
}
} // end Block Chain class