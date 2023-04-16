package com.wgplaner;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wgplaner.user.RegistrationUserAuthProfileController;
import com.wgplaner.user.UserAuthProfileDto;
import com.wgplaner.user.UserAuthProfileRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@Profile("test")
@ExtendWith(MockitoExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class RegistrationUserAuthProfileControllerTest {
    @Autowired
    private RegistrationUserAuthProfileController registrationController;
    @Autowired
    private PasswordEncoder passwordEncoder;

    private MockMvc mockMvc;
    @SpyBean
    private UserAuthProfileRepository repository;

    @BeforeEach
    public void setup() {
        mockMvc = MockMvcBuilders.standaloneSetup(registrationController).build();
    }

    @Test
    public void whenPostWithValidData_shouldCreateAndRespondWithId() throws Exception {
        String username = "username";
        String password = "Password123!";

        //when
        ResultActions resultActions = mockMvc.perform(MockMvcRequestBuilders.post("/register/new").contentType(MediaType.APPLICATION_JSON).content(asJsonString(new UserAuthProfileDto(username, password))));

        //assert
        resultActions.andExpect(MockMvcResultMatchers.status().isCreated());
        String id = resultActions.andReturn().getResponse().getContentAsString();

        verify(repository, times(1)).save(any());
        assertThat(passwordEncoder.matches(password, repository.findByUsername(username).getPassword())).isTrue();
        assertThat(repository.findByUsername(username).getId()).isGreaterThan(0);
        assertThat(id).matches("\\d+");
    }

    private static String asJsonString(final Object obj) {
        try {
            return new ObjectMapper().writeValueAsString(obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
