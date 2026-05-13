"""
Spark Security Log Analysis with Elasticsearch
"""
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, count, avg, max, min

# Spark session with JAR path
spark = SparkSession.builder \
    .appName("SecurityAnalytics") \
    .master("local[*]") \
    .config("spark.jars", "file:///home/wind/cybersec-platform/spark/elasticsearch-spark-30_2.12-8.11.0.jar") \
    .config("spark.es.nodes", "localhost") \
    .config("spark.es.port", "9200") \
    .config("spark.es.nodes.wan.only", "false") \
    .getOrCreate()

print("=" * 60)
print("SECURITY LOG ANALYSIS")
print("=" * 60)

try:
    # Elasticsearch se data load karo
    df = spark.read \
        .format("org.elasticsearch.spark.sql") \
        .option("es.resource", "security-logs") \
        .load()

    print(f"Total records: {df.count()}")
    print("\nSample data:")
    df.show(5, truncate=False)

    print("\n=== User Activity Summary ===")
    df.groupBy("user_id") \
      .agg(count("*").alias("total_actions"),
           avg("files_accessed").alias("avg_files"),
           max("files_accessed").alias("max_files")) \
      .orderBy(col("total_actions").desc()) \
      .show(10)

    print("\n=== Suspicious Locations ===")
    if 'location' in df.columns:
        df.filter(col("location") != "Pakistan") \
          .groupBy("user_id", "location") \
          .count() \
          .show()

except Exception as e:
    print(f"ES not available: {e}")
    print("\nCreating sample analysis...")

    # Sample test data
    data = [
        ("ali", "login", 10, "Pakistan", "laptop"),
        ("ali", "download", 5000, "Russia", "unknown"),
        ("sara", "login", 20, "Pakistan", "mobile"),
        ("ahmed", "logout", 5, "Pakistan", "laptop"),
        ("fatima", "file_access", 100, "UAE", "laptop"),
    ]

    df = spark.createDataFrame(data, ["user_id", "action", "files_accessed", "location", "device"])

    print("Sample Data:")
    df.show()

    print("\nUser Activity:")
    df.groupBy("user_id").agg(count("*").alias("count")).show()

    print("\nSuspicious Activity (non-Pakistan):")
    df.filter(col("location") != "Pakistan").show()

print("\n" + "=" * 60)
print("Analysis Complete!")
print("=" * 60)

spark.stop()
