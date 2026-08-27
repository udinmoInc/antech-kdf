// Backend sketch: register/login with the Java JNA binding.

package com.udinmo.antech.example;

import com.udinmo.antech.AntechKdf;

public class UserService {
  public String registerUser(String password) {
    return AntechKdf.hash(password);
  }

  public boolean loginUser(String password, String storedHash) {
    return AntechKdf.verify(password, storedHash);
  }
}
