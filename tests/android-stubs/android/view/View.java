package android.view;
public class View {
  public interface OnClickListener { void onClick(View v); }
  public void setOnClickListener(OnClickListener l) {}
  public void setFitsSystemWindows(boolean b) {}
  public boolean post(Runnable r) { return true; }
}
