import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashSet;


public class TxHandler {
	private UTXOPool uPool;

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    public TxHandler(UTXOPool utxoPool) {
    	uPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
    	ArrayList<UTXO> utxoFromInputs = new ArrayList<UTXO>(tx.getInputs().size());
	
    	ArrayList<Transaction.Input> inputs = tx.getInputs();
    	double InputValueSum = 0;
    	double OutputValueSum = 0;
    
    	// Check inputs
    	for(int i=0 ; i<inputs.size(); i++) {
    		Transaction.Input ip = inputs.get(i);
    		// Check if input is in UTXO pool
    		UTXO u = new UTXO(ip.prevTxHash, ip.outputIndex);
    		if(!uPool.contains(u))
    			return false;
    		else {
    			PublicKey key = uPool.getTxOutput(u).address;
    			double value = uPool.getTxOutput(u).value;
    		
    			InputValueSum += value;
    			utxoFromInputs.add(new UTXO(ip.prevTxHash, ip.outputIndex));
    		
    		// Check if signature are valid
    		if(! Crypto.verifySignature(key, tx.getRawDataToSign(i), 
    				ip.signature))
    			return false;
    		}
    	}
    	
    	// Check if there's UTXO claimed multiple times
    	if(new HashSet<UTXO>(utxoFromInputs).size() != utxoFromInputs.size())
    		return false;
    	
    	for(Transaction.Output ot : tx.getOutputs()) {
    		OutputValueSum += ot.value;
    		
    		// Check if all output values are not negative
    		if(ot.value < 0) 
    			return false; 		
    	}
    	
    	// Check if sum of all input values is greater than or equal to 
    	// the sum of all output values
    	if(InputValueSum < OutputValueSum)
    		return false;
    	
    	return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
    	ArrayList<Transaction> validTransactions = new ArrayList<Transaction>();
    	for(int i=0; i<possibleTxs.length; i++) {
    		Transaction tx = possibleTxs[i];
    		
    		if(isValidTx(tx)) {
				validTransactions.add(tx);
    			// Update UTXO pool accordingly
    			
    			// Remove all UTXOs of inputs from UTXO Pool
    			ArrayList<Transaction.Input> inputAll = tx.getInputs();
    			for(Transaction.Input ip : inputAll) {
    				UTXO ut = new UTXO(ip.prevTxHash, ip.outputIndex);
    				uPool.removeUTXO(ut);
    			}

    			// Add all UTXOs of outputs into UTXO Pool
    			ArrayList<Transaction.Output> outputAll = tx.getOutputs();
    			for(int j=0; j<outputAll.size(); j++) {
    				UTXO ut = new UTXO(tx.getHash(), j);
    				uPool.addUTXO(ut, outputAll.get(j));
    			}
    		}
    	}
    	
    	return (Transaction []) validTransactions.toArray(new Transaction[0]);
    }

}
