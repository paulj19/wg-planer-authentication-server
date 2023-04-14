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
@NotNull(message = """
            password must meet the following criteria must be start-of-string
             a digit must occur at least once
             a lower case letter must occur at least once
             an upper case letter must occur at least once
             a special character must occur at least once
             no whitespace allowed in the entire string
             anything, at least eight places though end-of-string
            """)
@NotEmpty(message = """
            password must meet the following criteria must be start-of-string
             a digit must occur at least once
             a lower case letter must occur at least once
             an upper case letter must occur at least once
             a special character must occur at least once
             no whitespace allowed in the entire string
             anything, at least eight places though end-of-string
            """)
@Pattern(regexp = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*()\\-_\"=+{};:,<.>])(?=\\S+$).{8,}$", message = """
            password must meet the following criteria must be start-of-string
             a digit must occur at least once
             a lower case letter must occur at least once
             an upper case letter must occur at least once
             a special character must occur at least once
             no whitespace allowed in the entire string
             anything, at least eight places though end-of-string
            """)
@Constraint(validatedBy = {})
public @interface ValidPassword {
    String message() default "";

    Class<?>[] groups() default {};

    Class<? extends Payload>[] payload() default {};
}
