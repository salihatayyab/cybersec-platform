from pyspark.sql import SparkSession
from pyspark.sql.functions import col, count, avg

spark = SparkSession.builder \
    .appName("SecurityAnalytics") \
    .config("spark.es.nodes", "localhost") \
    .config("spark.es.port", "9200") \
    .getOrCreate()

# Elasticsearch se data load karo
df = spark.read \
    .format("org.elasticsearch.spark.sql") \
    .load("security-logs")

print("=== User Activity Summary ===")
df.groupBy("user_id") \
  .agg(
      count("*").alias("total_actions"),
      avg("files_accessed").alias("avg_files")
  ) \
  .show()

print("=== Suspicious Locations ===")
df.filter(col("location") != "Pakistan") \
  .groupBy("user_id", "location") \
  .count() \
  .show()
