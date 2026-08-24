// Backend Integration Example: Java + Spring Boot
// Demonstrates strictly where AntechKdf.hash() and AntechKdf.verify() are invoked.

package com.antech.example;

import org.antech.AntechKdf;

pub class UserService {
    public String registerUser(String password) {
        return AntechKdf.hash(password);
    }

    public boolean loginUser(String password, String storedHash) {
        return AntechKdf.verify(password, storedHash);
    }
}
