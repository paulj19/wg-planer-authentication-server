package com.wgplaner.user;

import javax.validation.Constraint;
import javax.validation.Payload;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.TYPE, ElementType.FIELD, ElementType.PARAMETER})
@Retention(RetentionPolicy.RUNTIME)
@NotNull(message = "username must be between 4 and 32 chars, only letters numbers and . with a word prefix and suffix")
@NotEmpty(message = "username must be between 4 and 32 chars, only letters numbers and . with a word prefix and suffix")
//https://stackoverflow.com/questions/2053335/what-should-be-the-valid-characters-in-usernames
@Pattern(regexp = "^\\w(?:\\w|[.-](?=\\w)){3,31}$", message = "username must be between 4 and 32 chars, only letters numbers and . with a word prefix and suffix")
@Constraint(validatedBy = { })
public @interface ValidUsername {
    String message() default "";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
