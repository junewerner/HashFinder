package com.converge;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class HashFinder implements BurpExtension
{
    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName("HashFinder");

        api.scanner().registerScanCheck(new HashChecks(api));
    }
}