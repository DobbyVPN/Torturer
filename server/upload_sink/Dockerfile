FROM scratch

COPY upload-sink /upload-sink

# Render mounts secret files with group 1000. Keep the process unprivileged
# while granting it only the group access needed to read the one path file.
USER 65532:1000
ENTRYPOINT ["/upload-sink"]
CMD ["--path-file=/etc/secrets/upload-path"]
