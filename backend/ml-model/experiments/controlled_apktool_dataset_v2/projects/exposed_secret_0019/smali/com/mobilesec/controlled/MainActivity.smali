.class public Lcom/mobilesec/controlled/MainActivity;
.super Landroid/app/Activity;

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    const-string v0, "-----BEGIN PRIVATE KEY-----"
    invoke-static {v0}, Lcom/mobilesec/controlled/MainActivity;->sink(Ljava/lang/String;)V
    const-string v0, "controlled-private-key-body-19"
    invoke-static {v0}, Lcom/mobilesec/controlled/MainActivity;->sink(Ljava/lang/String;)V
    const-string v0, "-----END PRIVATE KEY-----"
    invoke-static {v0}, Lcom/mobilesec/controlled/MainActivity;->sink(Ljava/lang/String;)V
    return-void
.end method

.method public static sink(Ljava/lang/String;)V
    .locals 0
    return-void
.end method
