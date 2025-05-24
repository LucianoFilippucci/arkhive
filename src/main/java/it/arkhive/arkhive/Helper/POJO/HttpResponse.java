package it.arkhive.arkhive.Helper.POJO;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.time.LocalDateTime;

@Data
@SuperBuilder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class HttpResponse<T> {
    protected LocalDateTime timestamp;
    protected Integer statusCode;
    protected String message;
    protected T data;
}
