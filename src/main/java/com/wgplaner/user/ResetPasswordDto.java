package com.wgplaner.user;

public record ResetPasswordDto(
    Long oid,
    String password
) {
}
