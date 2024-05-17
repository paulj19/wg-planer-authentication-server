package com.wgplaner.user;

public record UserAuthProfileDto(
    @ValidUsername
    String username,
    @ValidPassword String password,
    String floorId
) {
}
