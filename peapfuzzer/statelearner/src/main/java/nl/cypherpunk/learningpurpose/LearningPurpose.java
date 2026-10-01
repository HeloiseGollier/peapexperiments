package nl.cypherpunk.learningpurpose;

import java.sql.Connection;
import java.util.ArrayList;

import net.automatalib.words.WordBuilder;
import net.automatalib.words.impl.SimpleAlphabet;
import nl.cypherpunk.statelearner.LearningConfig;
import nl.cypherpunk.statelearner.LogOracle;
import nl.cypherpunk.statelearner.Utils;

public class LearningPurpose {

	private final Connection dbConn;
	private static final String DISABLE_SYM = "-";
	private final ArrayList<String> resetOutputs;
	private WordBuilder<String> query;
	private WordBuilder<String> response;
	private SimpleAlphabet<String> alphabet;

	private boolean isDisabled;

	public LearningPurpose(LearningConfig config) {
		this.dbConn = config.getDbConn();

		// Reset/Disable outputs
		this.resetOutputs = config.getDisable_outputs();
		this.query = new WordBuilder<>();
		this.response = new WordBuilder<>();
		this.alphabet = config.getAlphabet();
		this.isDisabled = false;
	}

	public void processInput(String input) {
		this.query.append(input);
	}

	public void processOutput(String output) {
		this.response.append(output);
//		if (resetOutputs.contains(Utils.stripTimestamp(output))) {
//			this.isDisabled = true;
//		}
		for (String dis: this.resetOutputs){
            if (output.contains(dis)) {
                this.isDisabled = true;
                break;
            }
		}

	}

	public boolean isDisabled() {
		return isDisabled;
	}
	public void reset() {
		this.isDisabled = false;
		this.response.clear();
		this.query.clear();
	}

	private void optimiseDisableState() {
		if (query.size() != response.size()) {
			// This shouldn't happen, but if it does, we can safely return null
			return;
		}
		for (String s : this.alphabet) {
			String q = this.query.toWord() + " " + s;
			String r = this.response.toWord() + " " + LogOracle.DISABLE_OUTPUT;
			Utils.cacheStringQueryResponse(q, r, dbConn, true);
		}
	}

	public void optimise() {
		if (isDisabled) {
			optimiseDisableState();
		}
	}

}
