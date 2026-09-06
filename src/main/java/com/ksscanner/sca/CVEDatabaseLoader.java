package com.ksscanner.sca;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

public class CVEDatabaseLoader {

    public List<CVERecord> load(
            String file)
            throws Exception {

        List<CVERecord> list =
                new ArrayList<>();

        BufferedReader reader =
                new BufferedReader(
                        new FileReader(file));

        String line;

        // Skip CSV header
        reader.readLine();

        while ((line = reader.readLine()) != null) {

            String[] parts =
                    line.split(",");

            if (parts.length < 8) {
                continue;
            }

            list.add(
                    new CVERecord(
                            parts[0], // package
                            parts[1], // version
                            parts[2], // cve
                            parts[3], // severity
                            parts[4], // cvss
                            parts[5], // description
                            parts[6], // recommendation
                            parts[7]  // reference
                    ));
        }

        reader.close();

        return list;
    }
}