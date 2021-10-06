package app.dassana.core.contentmanager.infra;

import static app.dassana.core.workflow.processor.Decorator.DASSANA_KEY;

import app.dassana.core.contentmanager.RemoteContentDownloadApi;
import app.dassana.core.workflow.model.WorkflowOutputWithRisk;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import java.nio.charset.Charset;
import java.time.Duration;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import javax.inject.Singleton;
import org.apache.commons.io.IOUtils;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.paginators.ListObjectsV2Iterable;

@Singleton
public class S3Manager implements RemoteContentDownloadApi {

  private final S3Client s3Client;
  public static final String WORKFLOW_PATH_IN_S3 = "workflows/";
  public static final String LAST_UPDATED_KEY = "content-last-updated";


  public S3Manager(S3Client s3Client) {
    this.s3Client = s3Client;

  }


  private static final Logger logger = LoggerFactory.getLogger(S3Manager.class);

  String s3Bucket = System.getenv("dassanaBucket");

  LoadingCache<String, Long> cache =
      CacheBuilder.newBuilder().expireAfterAccess(Duration.ofSeconds(30)).build(new CacheLoader<>() {
        @Override
        public Long load(String s) {
          return getLastUpdatedValueFromS3();
        }
      });

  public String uploadedToS3(Optional<WorkflowOutputWithRisk> normalizationResult,
      String jsonToUpload) {

    DateTime now = DateTime.now(DateTimeZone.UTC);

    int min = now.minuteOfHour().get();
    int hour = now.hourOfDay().get();
    int day = now.dayOfMonth().get();
    int month = now.monthOfYear().get();
    int year = now.year().get();

    String alertsPrefix = "alerts".concat(
        "/year=".concat(String.valueOf(year)).concat(
            "/month=").concat(String.valueOf(month)).concat(
            "/day=").concat(String.valueOf(day)).concat(
            "/hour=").concat(String.valueOf(hour)).concat(
            "/min=").concat(String.valueOf(min)));

    String path;
    if (normalizationResult.isEmpty()) {
      path = alertsPrefix.concat("/unprocessed/").concat(UUID.randomUUID().toString());
    } else {
      path = alertsPrefix.concat("/".concat(UUID.randomUUID().toString()));
    }

    PutObjectRequest putObjectRequest = PutObjectRequest.builder().bucket(s3Bucket).
        key(path).
        build();

    s3Client.putObject(putObjectRequest, RequestBody.fromBytes(jsonToUpload.getBytes()));

    if (normalizationResult.isPresent()) {
      JSONObject dassanaDecoratedJsonObj = new JSONObject(jsonToUpload);
      JSONObject updatedDassanaObj = dassanaDecoratedJsonObj.getJSONObject(DASSANA_KEY)
          .put("alertKey", "s3://".concat(s3Bucket).concat("/").concat(path));
      dassanaDecoratedJsonObj.put(DASSANA_KEY, updatedDassanaObj);
      return dassanaDecoratedJsonObj.toString();
    } else {
      return jsonToUpload;
    }


  }

  @Override
  public List<String> downloadContent() {

    List<String> remoteContent = new LinkedList<>();

    Objects.requireNonNull(s3Bucket, "dassanaBucket must be specified as env var");
    //this is made available via CFT. Checkout "Variables" of DassanaEngine
    // and DassanaApi. In local dev setup, manually set it

    ListObjectsV2Request request = ListObjectsV2Request.builder().bucket(s3Bucket).prefix(WORKFLOW_PATH_IN_S3).build();
    ListObjectsV2Iterable response = s3Client.listObjectsV2Paginator(request);
    for (ListObjectsV2Response page : response) {
      for (S3Object object : page.contents()) {
        if (object.size() > 0) {
          try {
            s3Client
                .getObject(GetObjectRequest.builder().
                    bucket(s3Bucket).key(object.key())
                    .build(), (getObjectResponse, abortableInputStream) -> {//handle the object
                  String customWorkflowFile = IOUtils.toString(abortableInputStream, Charset.defaultCharset());
                  remoteContent.add(customWorkflowFile);
                  return null;
                });
          } catch (S3Exception exception) {//see https://github.com/aws/aws-sdk-java-v2/issues/428
            if (exception.toBuilder().statusCode() != 304) {
              throw new RuntimeException(exception);
            }
          }

        }
      }
    }//all s3 files have been processed now
    return remoteContent;
  }

  @Override
  public Long getLastUpdated(boolean useCache) throws ExecutionException {

    if (useCache) {
      return cache.get("foo");
    } else {
      return getLastUpdatedValueFromS3();
    }

  }


  private Long getLastUpdatedValueFromS3() {

    HeadObjectResponse headObjectResponse;
    try {
      headObjectResponse = s3Client.headObject(
          HeadObjectRequest.builder().bucket(s3Bucket).key(LAST_UPDATED_KEY).build());
      return headObjectResponse.lastModified().toEpochMilli();
    } catch (NoSuchKeyException noSuchKeyException) {
      return 0L;
    }

  }


}
